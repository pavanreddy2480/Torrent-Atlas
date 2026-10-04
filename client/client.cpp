#include "../common/protocol.hpp"
#include "../common/sha1.hpp"
#include "../common/secure_channel.hpp"
#include "client_types.hpp"
#include "command_utils.hpp"
#include "download_storage.hpp"
#include "network_utils.hpp"
#include "telemetry.hpp"

#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>
#include <vector>


static std::mutex activeDestinationsMutex;
static std::set<std::string> activeDestinations;

static void finishDownload(const std::shared_ptr<DownloadStatus> &status, bool failed,
                           const std::string &reason = "") {
    status->failureReason = failed ? reason : "";
    status->failed = failed;
    status->finalElapsedMicroseconds = elapsedMicroseconds(status->started);
    status->finished = true;
    if (!status->destinationKey.empty()) {
        std::lock_guard<std::mutex> lock(activeDestinationsMutex);
        activeDestinations.erase(status->destinationKey);
    }
}

static std::mutex sharedMutex;
static std::unordered_map<std::string, LocalFile> sharedFiles;
static std::mutex downloadsMutex;
static std::vector<std::shared_ptr<DownloadStatus>> downloads;
static std::mutex downloadThreadsMutex;
static std::vector<std::thread> downloadThreads;
static std::vector<Endpoint> trackerEndpoints;
static std::size_t leaderGuess = 0;
static std::string trackerPublicKey;
static std::mutex trackerMutex;
static u64 sessionId = 0;
static Endpoint peerEndpoint;
static std::atomic<bool> peerStopping{false};
static std::mutex peerMetricsMutex;
static std::unordered_map<std::string, PeerMetrics> peerMetrics;

static void recordPeerResult(const PeerInfo &peer, TransferResult result,
                             std::size_t bytes = 0, double seconds = 0.0) {
    std::lock_guard<std::mutex> lock(peerMetricsMutex);
    PeerMetrics &observed = peerMetrics[endpointKey(peer.endpoint)];
    switch (result) {
        case TransferResult::Success:
            ++observed.successes;
            observed.bytes += bytes;
            observed.transferSeconds += seconds;
            break;
        case TransferResult::NetworkFailure:
            ++observed.networkFailures;
            break;
        case TransferResult::AuthenticationFailure:
            ++observed.authenticationFailures;
            break;
        case TransferResult::IntegrityFailure:
            ++observed.integrityFailures;
            break;
        case TransferResult::Unavailable:
            break;
    }
}

static std::string keyFor(const std::string &group, const std::string &name) {
    return group + '\n' + name;
}

static bool trackerRequest(const std::string &command, std::string &response) {
    std::lock_guard<std::mutex> lock(trackerMutex);
    // Try the last known leader first; follow REDIRECTs, skip dead trackers,
    // and wait briefly while the cluster elects a leader.
    std::string request = "C\t" + std::to_string(sessionId) + "\t" + command;
    bool answered = false;
    for (int attempt = 0; attempt < 12 && !answered; ++attempt) {
        const Endpoint &target = trackerEndpoints[leaderGuess % trackerEndpoints.size()];
        if (!secureTrackerCall(target, trackerPublicKey, request, response)) {
            leaderGuess = (leaderGuess + 1) % trackerEndpoints.size();
            continue;
        }
        if (response.rfind("REDIRECT ", 0) == 0) {
            Endpoint leader;
            std::string address = response.substr(9, response.find('\t') - 9);
            for (std::size_t i = 0; i < trackerEndpoints.size(); ++i)
                if (parseEndpoint(address, leader) &&
                    endpointKey(trackerEndpoints[i]) == endpointKey(leader))
                    leaderGuess = i;
            continue;
        }
        if (response.rfind("ERR no leader elected yet", 0) == 0 ||
            response.rfind("ERR write not committed", 0) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }
        answered = true;
    }
    if (!answered) {
        response = "ERR tracker cluster unavailable";
        return false;
    }
    std::size_t tab = response.rfind('\t');
    u64 returnedSession = 0;
    if (tab == std::string::npos ||
        !parseUnsignedDecimal(response.substr(tab + 1), returnedSession))
        return false;
    sessionId = returnedSession;
    response.resize(tab);
    return true;
}

static std::string uploadCommand(const std::string &group, const std::string &name,
                                 const LocalFile &file) {
    return "upload_file " + group + " " + hexEncode(name) + " " +
           std::to_string(file.size) + " " + file.fullHash + " " + file.capability + " " +
           joinHashes(file.pieceHashes) + " " + peerEndpoint.ip + " " +
           std::to_string(peerEndpoint.port);
}

static void peerConnection(int fd) {
    timeval timeout{};
    timeout.tv_sec = 8;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string request;
    if (!receiveFrame(fd, request)) {
        close(fd);
        return;
    }
    std::vector<std::string> fields = split(request, '|');
    if (fields.size() != 6 || fields[0] != "21") {
        sendFrame(fd, "60|malformed");
        close(fd);
        return;
    }
    std::string group, name;
    if (!hexDecode(fields[1], group) || !hexDecode(fields[2], name) ||
        group.empty() || name.empty()) {
        sendFrame(fd, "60|encoding"); close(fd); return;
    }
    LocalFile file;
    {
        std::lock_guard<std::mutex> lock(sharedMutex);
        auto it = sharedFiles.find(keyFor(group, name));
        if (it == sharedFiles.end()) {
            sendFrame(fd, "60|unauthorized");
            close(fd);
            return;
        }
        file = it->second;
    }
    std::string key;
    AesGcmMessage requestMessage;
    if (!hexDecode(file.capability, key) || key.size() != 32 ||
        !hexDecode(fields[3], requestMessage.nonce) ||
        !hexDecode(fields[4], requestMessage.ciphertext) ||
        !hexDecode(fields[5], requestMessage.tag)) {
        sendFrame(fd, "60|encoding"); close(fd); return;
    }
    std::string requestAad =
        "21|" + fields[1] + "|" + fields[2];
    std::string requestPlain;
    if (!aes256GcmDecrypt(key, requestAad, requestMessage, requestPlain)) {
        sendFrame(fd, "60|aead"); close(fd); return;
    }
    // "<operation>\n<piece>\n<unix-seconds>"; stale requests are replays.
    std::vector<std::string> requestParts = split(requestPlain, '\n');
    long long requestTime = 0;
    if (requestParts.size() != 3) {
        sendFrame(fd, "60|request"); close(fd); return;
    }
    if (!parseFreshTimestamp(requestParts[2], requestTime)) {
        sendFrame(fd, "60|stale"); close(fd); return;
    }
    std::string operation = requestParts[0];
    std::size_t pieceIndex = 0;
    u64 parsedPiece = 0;
    if (!parseUnsignedDecimal(requestParts[1], parsedPiece) ||
        parsedPiece > std::numeric_limits<std::size_t>::max()) {
        sendFrame(fd, "60|piece"); close(fd); return;
    }
    pieceIndex = static_cast<std::size_t>(parsedPiece);
    if (operation != "BITMAP" &&
        (operation != "GET" || pieceIndex >= file.pieceHashes.size() ||
         pieceIndex >= file.available.size() || !file.available[pieceIndex])) {
        sendFrame(fd, "60|unauthorized");
        close(fd);
        return;
    }

    std::string responsePlain;
    if (operation == "BITMAP") {
        responsePlain.assign(file.available.begin(), file.available.end());
    } else if (operation == "GET") {
        std::size_t expected = static_cast<std::size_t>(
            std::min<u64>(PIECE_SIZE, file.size - static_cast<u64>(pieceIndex) * PIECE_SIZE));
        responsePlain.assign(expected, '\0');
        UniqueFd fileFd(open(file.path.c_str(), O_RDONLY));
        if (!fileFd) {
            sendFrame(fd, "60|open");
            close(fd);
            return;
        }
        std::size_t received = 0;
        off_t offset = static_cast<off_t>(pieceIndex * PIECE_SIZE);
        while (received < expected) {
            ssize_t count = pread(fileFd.get(), &responsePlain[received], expected - received,
                                  offset + static_cast<off_t>(received));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            received += static_cast<std::size_t>(count);
        }
        if (received != expected) {
            sendFrame(fd, "60|read");
            close(fd);
            return;
        }
    } else {
        sendFrame(fd, "60|operation");
        close(fd);
        return;
    }
    std::string responseAad = "30|" + requestAad + "|" + fields[3];
    AesGcmMessage responseMessage;
    if (!aes256GcmEncrypt(key, responseAad, responsePlain, responseMessage)) {
        sendFrame(fd, "60|encrypt");
        close(fd);
        return;
    }
    sendFrame(fd, "30|" + hexEncode(responseMessage.nonce) + "|" +
                  hexEncode(responseMessage.ciphertext) + "|" +
                  hexEncode(responseMessage.tag));
    close(fd);
}

static void peerServer() {
    UniqueFd listener(createListener(peerEndpoint.ip, peerEndpoint.port));
    if (!listener) {
        perror("peer listener");
        return;
    }
    std::mutex workersMutex;
    std::condition_variable workersCondition;
    std::size_t activeWorkers = 0;
    while (!peerStopping) {
        pollfd descriptor{listener.get(), POLLIN, 0};
        int ready = poll(&descriptor, 1, 200);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) continue;
        int fd = accept(listener.get(), nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (peerStopping) {
            close(fd);
            break;
        }
        {
            std::lock_guard<std::mutex> lock(workersMutex);
            ++activeWorkers;
        }
        std::thread([&, fd] {
            peerConnection(fd);
            {
                std::lock_guard<std::mutex> lock(workersMutex);
                --activeWorkers;
            }
            workersCondition.notify_all();
        }).detach();
    }
    listener.reset();
    std::unique_lock<std::mutex> lock(workersMutex);
    workersCondition.wait(lock, [&] { return activeWorkers == 0; });
}

static TransferResult securePeerRequest(const PeerInfo &peer,
                                        const std::string &group,
                                        const std::string &name,
                                        const std::string &capability,
                                        const std::string &plain,
                                        std::string &responsePlain, double &seconds,
                                        const std::shared_ptr<DownloadStatus> &status) {
    auto started = std::chrono::steady_clock::now();
    struct RequestTelemetry {
        std::shared_ptr<DownloadStatus> status;
        std::chrono::steady_clock::time_point started;
        u64 crypto = 0;
        explicit RequestTelemetry(std::shared_ptr<DownloadStatus> value)
            : status(std::move(value)), started(std::chrono::steady_clock::now()) {
            if (status) {
                ++status->wireRequests;
                ++status->activeRequests;
            }
        }
        ~RequestTelemetry() {
            if (!status) return;
            u64 total = elapsedMicroseconds(started);
            status->cryptoMicroseconds += crypto;
            status->networkMicroseconds += total > crypto ? total - crypto : 0;
            --status->activeRequests;
        }
    } telemetry(status);
    int fd = connectTcp(peer.endpoint.ip, peer.endpoint.port);
    if (fd < 0) return TransferResult::NetworkFailure;
    std::string key;
    if (!hexDecode(capability, key) || key.size() != 32) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    std::string requestAad =
        "21|" + hexEncode(group) + "|" + hexEncode(name);
    AesGcmMessage requestMessage;
    auto cryptoStarted = std::chrono::steady_clock::now();
    bool encrypted = aes256GcmEncrypt(
        key, requestAad, plain + "\n" + std::to_string(unixSeconds()), requestMessage);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!encrypted) {
        close(fd);
        return TransferResult::NetworkFailure;
    }
    std::string request = requestAad + "|" + hexEncode(requestMessage.nonce) + "|" +
                          hexEncode(requestMessage.ciphertext) + "|" +
                          hexEncode(requestMessage.tag);
    std::string response;
    bool ok = sendFrame(fd, request) && receiveFrame(fd, response);
    close(fd);
    seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (!ok) return TransferResult::NetworkFailure;
    std::vector<std::string> fields = split(response, '|');
    if (fields.size() >= 2 && fields[0] == "60") {
        if (fields[1] == "unauthorized" || fields[1] == "aead")
            return TransferResult::AuthenticationFailure;
        return TransferResult::Unavailable;
    }
    if (fields.size() != 4 || fields[0] != "30")
        return TransferResult::AuthenticationFailure;
    AesGcmMessage responseMessage;
    if (!hexDecode(fields[1], responseMessage.nonce) ||
        !hexDecode(fields[2], responseMessage.ciphertext) ||
        !hexDecode(fields[3], responseMessage.tag))
        return TransferResult::AuthenticationFailure;
    std::string responseAad =
        "30|" + requestAad + "|" + hexEncode(requestMessage.nonce);
    cryptoStarted = std::chrono::steady_clock::now();
    bool decrypted =
        aes256GcmDecrypt(key, responseAad, responseMessage, responsePlain);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!decrypted)
        return TransferResult::AuthenticationFailure;
    return TransferResult::Success;
}

static TransferResult fetchPieceData(const PeerInfo &peer, const std::string &group,
                                     const std::string &name, const std::string &capability,
                                     std::size_t index, const std::string &expectedHash,
                                     std::string &piece,
                                     const std::shared_ptr<DownloadStatus> &status) {
    double seconds = 0.0;
    TransferResult result = securePeerRequest(
        peer, group, name, capability, "GET\n" + std::to_string(index),
        piece, seconds, status);
    if (result != TransferResult::Success) {
        recordPeerResult(peer, result);
        recordDownloadFailure(status, result);
        return result;
    }
    const char *data = piece.data();
    std::size_t length = piece.size();
    Sha1 pieceHash;
    pieceHash.update(data, length);
    if (pieceHash.finalHex() != expectedHash) {
        recordPeerResult(peer, TransferResult::IntegrityFailure);
        recordDownloadFailure(status, TransferResult::IntegrityFailure);
        return TransferResult::IntegrityFailure;
    }

    recordPeerResult(peer, TransferResult::Success, length, seconds);
    return TransferResult::Success;
}

static TransferResult fetchPiece(const PeerInfo &peer, const std::string &group,
                                 const std::string &name, const std::string &capability,
                                 std::size_t index, const std::string &expectedHash,
                                 int outputFd,
                                 const std::shared_ptr<DownloadStatus> &status) {
    std::string piece;
    TransferResult result = fetchPieceData(
        peer, group, name, capability, index, expectedHash, piece, status);
    if (result == TransferResult::Success) {
        auto diskStarted = std::chrono::steady_clock::now();
        bool written = writePiece(outputFd, index, piece);
        if (status) status->diskMicroseconds += elapsedMicroseconds(diskStarted);
        if (!written) return TransferResult::NetworkFailure;
    }
    return result;
}

static bool fetchBitmap(const PeerInfo &peer, const std::string &group,
                        const std::string &name, const std::string &capability,
                        std::size_t pieceCount, std::vector<unsigned char> &bitmap,
                        const std::shared_ptr<DownloadStatus> &status) {
    std::string response;
    double seconds = 0.0;
    TransferResult result = securePeerRequest(
        peer, group, name, capability, "BITMAP\n0",
        response, seconds, status);
    if (result != TransferResult::Success || response.size() != pieceCount) {
        recordPeerResult(peer, result == TransferResult::Success
                                  ? TransferResult::AuthenticationFailure : result);
        recordDownloadFailure(status, result == TransferResult::Success
                                      ? TransferResult::AuthenticationFailure : result);
        return false;
    }
    bitmap.assign(response.begin(), response.end());
    for (unsigned char &piece : bitmap) piece = piece ? 1 : 0;
    recordPeerResult(peer, TransferResult::Success, 0, seconds);
    return true;
}

static void downloadFile(std::string group, std::string name, std::string destination,
                         LocalFile metadata, std::vector<PeerInfo> peers,
                         std::shared_ptr<DownloadStatus> status) {
    struct stat info{};
    if (stat(destination.c_str(), &info) == 0 && S_ISDIR(info.st_mode))
        destination += (destination.back() == '/' ? "" : "/") + name;
    std::string manifestPath = destination + ".resume";
    std::string temporary = destination + ".part";
    std::vector<unsigned char> resumedPieces;
    std::string storedTemporary;
    bool resuming = loadResume(manifestPath, group, name, metadata,
                               storedTemporary, resumedPieces) &&
                    storedTemporary == temporary;
    struct stat partialInfo{};
    resuming = resuming && stat(temporary.c_str(), &partialInfo) == 0 &&
               S_ISREG(partialInfo.st_mode) &&
               static_cast<u64>(partialInfo.st_size) == metadata.size;
    int output = open(temporary.c_str(), O_CREAT | O_RDWR | (resuming ? 0 : O_TRUNC), 0600);
    if (output < 0 || ftruncate(output, static_cast<off_t>(metadata.size)) < 0) {
        if (output >= 0) close(output);
        finishDownload(status, true, "unable to create destination file");
        return;
    }

    const std::size_t pieceCount = metadata.pieceHashes.size();
    status->totalBytes = metadata.size;
    status->discoveredPeers = peers.size();
    if (!resuming) resumedPieces.assign(pieceCount, 0);
    verifyStoredPieces(output, metadata, resumedPieces);
    status->completed = static_cast<std::size_t>(
        std::count(resumedPieces.begin(), resumedPieces.end(), static_cast<unsigned char>(1)));
    status->resumedPieces = status->completed.load();
    u64 resumedBytes = 0;
    for (std::size_t piece = 0; piece < resumedPieces.size(); ++piece) {
        if (!resumedPieces[piece]) continue;
        resumedBytes += std::min<u64>(
            PIECE_SIZE, metadata.size - static_cast<u64>(piece) * PIECE_SIZE);
    }
    status->verifiedBytes = resumedBytes;
    status->resumedVerifiedBytes = resumedBytes;
    auto resume = std::make_shared<ResumeState>();
    resume->manifestPath = manifestPath;
    resume->temporaryPath = temporary;
    resume->group = group;
    resume->name = name;
    resume->metadata = metadata;
    resume->verified = resumedPieces;
    {
        std::lock_guard<std::mutex> lock(resume->mutex);
        if (!saveResumeLocked(*resume)) {
            close(output);
            finishDownload(status, true, "unable to persist resume manifest");
            return;
        }
    }

    std::vector<std::vector<unsigned char>> peerBitmaps(peers.size());
    for (std::size_t peer = 0; peer < peers.size(); ++peer)
        if (fetchBitmap(peers[peer], group, name, metadata.capability, pieceCount,
                        peerBitmaps[peer], status))
            ++status->responsivePeers;

    std::vector<std::size_t> rarity(pieceCount, 0);
    for (const auto &bitmap : peerBitmaps)
        for (std::size_t piece = 0; piece < std::min(pieceCount, bitmap.size()); ++piece)
            rarity[piece] += bitmap[piece] != 0;
    if (!rarity.empty()) {
        std::size_t minimum = *std::min_element(rarity.begin(), rarity.end());
        status->rarePieces = static_cast<std::size_t>(
            std::count(rarity.begin(), rarity.end(), minimum));
    }

    std::vector<std::size_t> order;
    for (std::size_t piece = 0; piece < pieceCount; ++piece)
        if (!resumedPieces[piece]) order.push_back(piece);
    std::sort(order.begin(), order.end(), [&](std::size_t left, std::size_t right) {
        if (rarity[left] != rarity[right]) return rarity[left] < rarity[right];
        return left < right;
    });

    LocalFile partial = metadata;
    partial.path = temporary;
    partial.available = resumedPieces;
    {
        std::lock_guard<std::mutex> lock(sharedMutex);
        sharedFiles[keyFor(group, name)] = partial;
    }
    std::string partialRegistration;
    trackerRequest(uploadCommand(group, name, partial), partialRegistration);

    auto candidatesFor = [&](std::size_t piece) {
        std::vector<std::size_t> candidates;
        for (std::size_t peer = 0; peer < peers.size(); ++peer)
            if (piece < peerBitmaps[peer].size() && peerBitmaps[peer][piece])
                candidates.push_back(peer);
        if (candidates.size() > 1)
            std::rotate(candidates.begin(),
                        candidates.begin() + static_cast<std::ptrdiff_t>(piece % candidates.size()),
                        candidates.end());
        return candidates;
    };

    auto markAvailable = [&](std::size_t piece) {
        auto diskStarted = std::chrono::steady_clock::now();
        fsync(output);
        {
            std::lock_guard<std::mutex> lock(resume->mutex);
            if (piece < resume->verified.size()) resume->verified[piece] = 1;
            saveResumeLocked(*resume);
        }
        status->diskMicroseconds += elapsedMicroseconds(diskStarted);
        status->verifiedBytes += std::min<u64>(
            PIECE_SIZE, metadata.size - static_cast<u64>(piece) * PIECE_SIZE);
        {
            std::lock_guard<std::mutex> lock(sharedMutex);
            auto it = sharedFiles.find(keyFor(group, name));
            if (it != sharedFiles.end() && piece < it->second.available.size())
                it->second.available[piece] = 1;
        }
    };

    std::atomic<bool> failure{false};
    const std::size_t missingCount = order.size();
    const std::size_t normalCount = missingCount;
    std::atomic<std::size_t> nextOrder{0};
    std::size_t workerCount = normalCount == 0 ? 0 : std::min<std::size_t>(
        8, std::max<std::size_t>(1, std::min(peers.size(), normalCount)));
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < workerCount; ++worker) {
        workers.emplace_back([&] {
            for (;;) {
                if (status->cancelRequested) break;
                std::size_t position = nextOrder.fetch_add(1);
                if (position >= normalCount) break;
                std::size_t piece = order[position];
                bool obtained = false;
                for (int round = 0;
                     round < 3 && !obtained && !status->cancelRequested; ++round) {
                    std::vector<std::size_t> candidates = candidatesFor(piece);
                    for (std::size_t peer : candidates) {
                        if (status->cancelRequested) break;
                        TransferResult result = fetchPiece(
                            peers[peer], group, name, metadata.capability, piece,
                            metadata.pieceHashes[piece], output, status);
                        if (result == TransferResult::IntegrityFailure)
                            ++status->integrityFailures;
                        if (result == TransferResult::Success) {
                            obtained = true;
                            markAvailable(piece);
                            ++status->completed;
                            break;
                        }
                    }
                    if (!obtained && !status->cancelRequested)
                        std::this_thread::sleep_for(retryDelay(round));
                }
                if (!obtained && !status->cancelRequested) failure = true;
            }
        });
    }
    for (auto &worker : workers) worker.join();
    if (status->cancelRequested) {
        close(output);
        finishDownload(status, true, "cancelled by user; resume data retained");
        return;
    }

    close(output);

    u64 verifiedSize = 0;
    std::string verifiedHash;
    std::vector<std::string> verifiedPieces;
    if (failure) {
        finishDownload(status, true, "one or more pieces could not be reconstructed");
        return;
    }
    auto finalHashStarted = std::chrono::steady_clock::now();
    bool hashOk = hashFile(temporary, verifiedSize, verifiedHash, verifiedPieces);
    status->diskMicroseconds += elapsedMicroseconds(finalHashStarted);
    if (!hashOk) {
        finishDownload(status, true, "final file hashing failed");
        return;
    }
    if (verifiedSize != metadata.size || verifiedHash != metadata.fullHash) {
        finishDownload(status, true, "final SHA1 integrity check failed");
        return;
    }
    if (rename(temporary.c_str(), destination.c_str()) != 0) {
        finishDownload(status, true, "unable to move completed file into place");
        return;
    }
    unlink(manifestPath.c_str());
    metadata.path = destination;
    metadata.available.assign(pieceCount, 1);
    std::string registrationResponse;
    trackerRequest(uploadCommand(group, name, metadata), registrationResponse);
    {
        std::lock_guard<std::mutex> lock(sharedMutex);
        sharedFiles[keyFor(group, name)] = metadata;
    }
    finishDownload(status, false);
}

static bool executeCommand(const std::string &line, std::ostream &output) {
        std::vector<std::string> args = commandWords(line);
        if (args.empty()) return false;
        if (args[0] == "quit") return true;
        std::string command = canonicalCommand(args);
        std::size_t offset = command == args[0] ? 1 : 2;

        if (command == "upload_file") {
            if (args.size() < offset + 2) {
                output << "ERR usage: upload_file <group> <path>\n";
                return false;
            }
            std::string group = args[offset], path = args[offset + 1], name = baseName(path);
            LocalFile file;
            file.path = path;
            file.capability = hexEncode(randomBytes(32));
            if (file.capability.size() != 64) {
                output << "ERR secure random generation failed\n";
                return false;
            }
            if (!hashFile(path, file.size, file.fullHash, file.pieceHashes)) {
                output << "ERR upload file: " << std::strerror(errno) << '\n';
                return false;
            }
            file.available.assign(file.pieceHashes.size(), 1);
            std::string response;
            trackerRequest(uploadCommand(group, name, file), response);
            if (response.rfind("OK", 0) == 0) {
                std::vector<std::string> responseWords = commandWords(response);
                if (responseWords.size() >= 4 && responseWords[3].size() == 64)
                    file.capability = responseWords[3];
                std::lock_guard<std::mutex> lock(sharedMutex);
                sharedFiles[keyFor(group, name)] = file;
                output << "OK file shared\n";
            } else {
                output << response << '\n';
            }
            return false;
        }
        if (command == "download_file" || command == "resume_download") {
            if (args.size() < offset + 3) {
                output << "ERR usage: " << command
                       << " <group> <file-name> <destination>\n";
                return false;
            }
            std::string group = args[offset], name = args[offset + 1], destination = args[offset + 2];
            std::string destinationKey = resolvedDestination(destination, name);
            struct stat destinationInfo{};
            if (stat(destinationKey.c_str(), &destinationInfo) == 0) {
                output << "ERR destination already exists: " << destinationKey << '\n';
                return false;
            }
            {
                std::lock_guard<std::mutex> lock(activeDestinationsMutex);
                if (!activeDestinations.insert(destinationKey).second) {
                    output << "ERR destination is already being downloaded: "
                           << destinationKey << '\n';
                    return false;
                }
            }
            std::string response;
            if (!trackerRequest("download_file " + group + " " + hexEncode(name), response) ||
                response.rfind("META ", 0) != 0) {
                std::lock_guard<std::mutex> lock(activeDestinationsMutex);
                activeDestinations.erase(destinationKey);
                output << response << '\n';
                return false;
            }
            std::istringstream metadataStream(response);
            std::string marker, hashes, peersText;
            LocalFile metadata;
            metadataStream >> marker >> metadata.size >> metadata.fullHash >> metadata.capability >>
                hashes >> peersText;
            metadata.pieceHashes = hashes == "-" ? std::vector<std::string>{} : split(hashes, ',');
            std::string capabilityBytes;
            std::size_t expectedPieces = 0;
            metadataStream >> std::ws;
            bool metadataValid = metadataStream.eof() && marker == "META" &&
                isSha1Hex(metadata.fullHash) &&
                isHexInteger(metadata.capability, 64, 64) &&
                hexDecode(metadata.capability, capabilityBytes) &&
                capabilityBytes.size() == 32 &&
                pieceCountForSize(metadata.size, expectedPieces) &&
                metadata.pieceHashes.size() == expectedPieces &&
                std::all_of(metadata.pieceHashes.begin(),
                            metadata.pieceHashes.end(), isSha1Hex);
            if (!metadataValid) {
                std::lock_guard<std::mutex> lock(activeDestinationsMutex);
                activeDestinations.erase(destinationKey);
                output << "ERR invalid tracker metadata\n";
                return false;
            }
            std::vector<PeerInfo> peers;
            for (const auto &peerText : split(peersText, ',')) {
                Endpoint endpoint;
                if (parseEndpoint(peerText, endpoint))
                    peers.push_back({endpoint});
            }
            if (peers.empty()) {
                std::lock_guard<std::mutex> lock(activeDestinationsMutex);
                activeDestinations.erase(destinationKey);
                output << "ERR no valid peer endpoints\n";
                return false;
            }
            auto status = std::make_shared<DownloadStatus>();
            status->group = group;
            status->name = name;
            status->total = metadata.pieceHashes.size();
            status->destinationKey = destinationKey;
            {
                std::lock_guard<std::mutex> lock(downloadsMutex);
                downloads.push_back(status);
            }
            {
                std::lock_guard<std::mutex> lock(downloadThreadsMutex);
                downloadThreads.emplace_back(
                    downloadFile, group, name, destination, metadata, peers, status);
            }
            output << "OK download started\n";
            return false;
        }
        if (command == "show_downloads") {
            std::lock_guard<std::mutex> lock(downloadsMutex);
            for (const auto &status : downloads) {
                char state = status->finished ? (status->failed ? 'F' : 'C') : 'D';
                output << '[' << state << "] [" << status->group << "] " << status->name;
                if (!status->finished)
                    output << " (" << status->completed << '/' << status->total << " pieces)";
                output << " rare=" << status->rarePieces
                       << " resumed=" << status->resumedPieces
                       << " integrity-failures=" << status->integrityFailures;
                if (status->failed && !status->failureReason.empty())
                    output << " reason=\"" << status->failureReason << '"';
                output << '\n';
            }
            return false;
        }
        if (command == "cancel_download") {
            if (args.size() < offset + 1) {
                output << "ERR usage: cancel download <file-name>\n";
                return false;
            }
            std::lock_guard<std::mutex> lock(downloadsMutex);
            for (auto it = downloads.rbegin(); it != downloads.rend(); ++it) {
                const auto &status = *it;
                if (status->name == args[offset] && !status->finished) {
                    status->cancelRequested = true;
                    output << "OK cancellation requested\n";
                    return false;
                }
            }
            output << "ERR no active download with that name\n";
            return false;
        }
        if (command == "peer_stats" || command == "show_peers") {
            std::lock_guard<std::mutex> lock(peerMetricsMutex);
            if (peerMetrics.empty()) {
                output << "No peer observations yet\n";
                return false;
            }
            std::map<std::string, PeerMetrics> sortedMetrics(
                peerMetrics.begin(), peerMetrics.end());
            for (const auto &entry : sortedMetrics) {
                const PeerMetrics &observed = entry.second;
                double throughput = observed.transferSeconds > 0.0
                    ? static_cast<double>(observed.bytes) / observed.transferSeconds /
                      (1024.0 * 1024.0)
                    : 0.0;
                output << entry.first << " speed=" << std::fixed
                       << std::setprecision(1) << throughput << "MiB/s"
                       << " ok=" << observed.successes
                       << " network=" << observed.networkFailures
                       << " auth=" << observed.authenticationFailures
                       << " corrupt=" << observed.integrityFailures << '\n';
            }
            return false;
        }
        if (command == "stats") {
            std::vector<std::shared_ptr<DownloadStatus>> snapshot;
            {
                std::lock_guard<std::mutex> lock(downloadsMutex);
                snapshot = downloads;
            }
            if (snapshot.empty()) {
                output << "No downloads recorded\n";
                return false;
            }
            u64 aggregateBytes = 0, aggregateTotal = 0;
            double aggregateSeconds = 0.0;
            for (const auto &status : snapshot) {
                u64 finalMicros = status->finalElapsedMicroseconds.load();
                double elapsed = std::max(0.001, finalMicros
                    ? finalMicros / 1000000.0
                    : std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - status->started).count());
                u64 verified = status->verifiedBytes.load();
                u64 resumed = status->resumedVerifiedBytes.load();
                u64 transferred = verified > resumed ? verified - resumed : 0;
                double speed = static_cast<double>(transferred) / elapsed / (1024.0 * 1024.0);
                double progress = status->totalBytes
                    ? 100.0 * static_cast<double>(verified) / status->totalBytes : 100.0;
                double eta = speed > 0.0 && verified < status->totalBytes
                    ? static_cast<double>(status->totalBytes - verified) /
                      (speed * 1024.0 * 1024.0)
                    : 0.0;
                u64 crypto = status->cryptoMicroseconds.load();
                u64 network = status->networkMicroseconds.load();
                u64 disk = status->diskMicroseconds.load();
                u64 measured = crypto + network + disk;
                double cryptoPercent = measured
                    ? 100.0 * static_cast<double>(crypto) / measured : 0.0;
                char state = status->finished ? (status->failed ? 'F' : 'C') : 'D';
                output << '[' << state << "] [" << status->group << "] " << status->name << '\n'
                       << "  progress: " << std::fixed << std::setprecision(1)
                       << progress << "% (" << status->completed << '/' << status->total
                       << " pieces, " << verified / (1024 * 1024) << '/'
                       << status->totalBytes / (1024 * 1024) << " MiB)\n"
                       << "  speed: " << speed << " MiB/s"
                       << "  elapsed: " << elapsed << "s"
                       << "  eta: " << eta << "s\n"
                       << "  peers: " << status->responsivePeers << '/'
                       << status->discoveredPeers << " responsive, "
                       << status->activeRequests << " requests active\n"
                       << "  scheduler: rare=" << status->rarePieces
                       << " resumed=" << status->resumedPieces << '\n'
                       << "  reliability: retries=" << status->retries
                       << " network=" << status->networkFailures
                       << " auth=" << status->authenticationFailures
                       << " unavailable=" << status->unavailableResponses
                       << " corrupt=" << status->integrityFailures << '\n'
                       << "  security: crypto=" << crypto / 1000.0 << "ms"
                       << " network/wait=" << network / 1000.0 << "ms"
                       << " disk=" << disk / 1000.0 << "ms"
                       << " crypto-overhead=" << cryptoPercent << "%\n";
                aggregateBytes += transferred;
                aggregateTotal += status->totalBytes;
                aggregateSeconds = std::max(aggregateSeconds, elapsed);
            }
            double aggregateSpeed = aggregateSeconds > 0.0
                ? static_cast<double>(aggregateBytes) / aggregateSeconds /
                  (1024.0 * 1024.0)
                : 0.0;
            output << "Aggregate: " << snapshot.size() << " downloads, "
                   << aggregateSpeed << " MiB/s, "
                   << aggregateTotal / (1024 * 1024) << " MiB scheduled\n";
            return false;
        }

        std::string trackerCommand = command;
        for (std::size_t i = offset; i < args.size(); ++i) trackerCommand += " " + args[i];
        if ((command == "list_files" || command == "stop_share") && args.size() > offset + 1) {
            trackerCommand = command + " " + args[offset] + " " + hexEncode(args[offset + 1]);
        }
        std::string response;
        trackerRequest(trackerCommand, response);
        if (command == "login" || command == "create_user") {
            secureErase(trackerCommand);
            for (std::string &argument : args) secureErase(argument);
        }
        if (command == "list_files" && response.rfind("OK", 0) == 0) {
            for (std::size_t i = 1; i < commandWords(response).size(); ++i) {
                std::string decoded;
                if (hexDecode(commandWords(response)[i], decoded))
                    output << decoded << '\n';
            }
        } else {
            output << response << '\n';
        }
        if (command == "stop_share" && response.rfind("OK", 0) == 0 && args.size() >= offset + 2) {
            std::lock_guard<std::mutex> lock(sharedMutex);
            sharedFiles.erase(keyFor(args[offset], args[offset + 1]));
        }
        if (command == "logout" && response.rfind("OK", 0) == 0) {
            std::lock_guard<std::mutex> lock(sharedMutex);
            sharedFiles.clear();
        }
        if (command == "leave_group" && response.rfind("OK", 0) == 0 &&
            args.size() >= offset + 1) {
            const std::string prefix = args[offset] + '\n';
            std::lock_guard<std::mutex> lock(sharedMutex);
            for (auto it = sharedFiles.begin(); it != sharedFiles.end();) {
                if (it->first.rfind(prefix, 0) == 0) it = sharedFiles.erase(it);
                else ++it;
            }
        }
        return false;
}

static int runCli() {
    std::cout << "Client listening on " << peerEndpoint.ip << ':' << peerEndpoint.port << '\n';
    std::string line;
    while (std::cout << "> " && std::getline(std::cin, line)) {
        if (executeCommand(line, std::cout)) break;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || !parseEndpoint(argv[1], peerEndpoint) ||
        !loadTrackerInfo(argv[2], trackerEndpoints, trackerPublicKey)) {
        std::cerr << "usage: " << argv[0]
                  << " <peer-ip:port> client.conf\n"
                  << "client.conf lists the trackers' IP:PORT and the cluster public key; "
                     "torrent_keygen creates it\n";
        return 1;
    }
    std::thread peerThread(peerServer);
    int result = runCli();
    {
        std::lock_guard<std::mutex> lock(downloadsMutex);
        for (const auto &download : downloads)
            if (!download->finished) download->cancelRequested = true;
    }
    {
        std::lock_guard<std::mutex> lock(downloadThreadsMutex);
        for (auto &thread : downloadThreads)
            if (thread.joinable()) thread.join();
        downloadThreads.clear();
    }
    peerStopping = true;
    peerThread.join();
    return result;
}

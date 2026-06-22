#include "../common/protocol.hpp"
#include "../common/sha1.hpp"
#include "../common/secure_crypto.hpp"
#include "client_types.hpp"
#include "command_utils.hpp"
#include "download_storage.hpp"
#include "network_utils.hpp"
#include "telemetry.hpp"
#include "tui_model.hpp"
#include "tui_theme.hpp"

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

#ifdef TORRENT_ENABLE_FTXUI
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#endif

static std::mutex activeDestinationsMutex;
static std::set<std::string> activeDestinations;

static void finishDownload(const std::shared_ptr<DownloadStatus> &status, bool failed,
                           const std::string &reason = "") {
    {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.failureReason = failed ? reason : "";
        status->telemetry.integrityVerified = !failed;
        for (auto &worker : status->telemetry.workers) {
            worker.piece.reset();
            worker.peer.clear();
            worker.state = failed ? "stopped" : "complete";
        }
    }
    sampleDownloadSpeed(status, true);
    addProtocolEvent(status, failed
        ? "Download failed: " + (reason.empty() ? std::string("transfer failed") : reason)
        : "Full-file SHA1 verified; destination committed");
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
static std::vector<Endpoint> trackers;
static std::size_t preferredTracker = 0;
static std::mutex trackerMutex;
static u64 sessionId = 0;
static Endpoint peerEndpoint;
static std::mutex reputationMutex;
static std::unordered_map<std::string, PeerReputation> reputations;

static double reputationScore(const PeerInfo &peer) {
    std::lock_guard<std::mutex> lock(reputationMutex);
    const PeerReputation &reputation = reputations[endpointKey(peer.endpoint)];
    if (reputation.blacklistedUntil > std::time(nullptr)) return -1e12;
    double throughput = reputation.transferSeconds > 0.0
        ? static_cast<double>(reputation.bytes) / reputation.transferSeconds / (1024.0 * 1024.0)
        : 0.0;
    return 100.0 + std::min(throughput, 100.0) + reputation.successes * 0.5 -
           reputation.networkFailures * 2.0 - reputation.authenticationFailures * 25.0 -
           reputation.integrityFailures * 40.0;
}

static bool peerBlacklisted(const PeerInfo &peer) {
    std::lock_guard<std::mutex> lock(reputationMutex);
    return reputations[endpointKey(peer.endpoint)].blacklistedUntil > std::time(nullptr);
}

static void recordPeerResult(const PeerInfo &peer, TransferResult result,
                             std::size_t bytes = 0, double seconds = 0.0) {
    std::lock_guard<std::mutex> lock(reputationMutex);
    PeerReputation &reputation = reputations[endpointKey(peer.endpoint)];
    switch (result) {
        case TransferResult::Success:
            ++reputation.successes;
            reputation.bytes += bytes;
            reputation.transferSeconds += seconds;
            break;
        case TransferResult::NetworkFailure:
            ++reputation.networkFailures;
            break;
        case TransferResult::AuthenticationFailure:
            ++reputation.authenticationFailures;
            break;
        case TransferResult::IntegrityFailure:
            ++reputation.integrityFailures;
            break;
        case TransferResult::Unavailable:
            break;
    }
    if (reputation.authenticationFailures + reputation.integrityFailures >= 3)
        reputation.blacklistedUntil = std::time(nullptr) + 300;
}

static std::string keyFor(const std::string &group, const std::string &name) {
    return group + '\n' + name;
}

static bool trackerRequest(const std::string &command, std::string &response) {
    std::lock_guard<std::mutex> lock(trackerMutex);
    for (std::size_t attempt = 0; attempt < trackers.size(); ++attempt) {
        std::size_t index = (preferredTracker + attempt) % trackers.size();
        int fd = connectTcp(trackers[index].ip, trackers[index].port);
        if (fd < 0) continue;
        std::string request = "C\t" + std::to_string(sessionId) + "\t" + command;
        bool ok = sendFrame(fd, request) && receiveFrame(fd, response);
        close(fd);
        if (!ok) continue;
        std::size_t tab = response.rfind('\t');
        if (tab == std::string::npos) return false;
        try { sessionId = static_cast<u64>(std::stoull(response.substr(tab + 1))); }
        catch (...) { return false; }
        response.resize(tab);
        preferredTracker = index;
        return true;
    }
    response = "ERR both trackers are unavailable";
    return false;
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
    std::vector<std::string> requestParts = split(requestPlain, '\n');
    if (requestParts.size() != 2) {
        sendFrame(fd, "60|request"); close(fd); return;
    }
    std::string operation = requestParts[0];
    std::size_t pieceIndex = 0;
    try { pieceIndex = static_cast<std::size_t>(std::stoull(requestParts[1])); }
    catch (...) { sendFrame(fd, "60|piece"); close(fd); return; }
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
        int fileFd = open(file.path.c_str(), O_RDONLY);
        if (fileFd < 0) {
            sendFrame(fd, "60|open");
            close(fd);
            return;
        }
        std::size_t received = 0;
        off_t offset = static_cast<off_t>(pieceIndex * PIECE_SIZE);
        while (received < expected) {
            ssize_t count = pread(fileFd, &responsePlain[received], expected - received,
                                  offset + static_cast<off_t>(received));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            received += static_cast<std::size_t>(count);
        }
        close(fileFd);
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
    int listener = createListener(peerEndpoint.ip, peerEndpoint.port);
    if (listener < 0) {
        perror("peer listener");
        return;
    }
    for (;;) {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        std::thread(peerConnection, fd).detach();
    }
    close(listener);
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
    bool encrypted =
        aes256GcmEncrypt(key, requestAad, plain, requestMessage);
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
        const char *reason = result == TransferResult::NetworkFailure ? "network" :
                             result == TransferResult::AuthenticationFailure ? "authentication" :
                             result == TransferResult::IntegrityFailure ? "integrity" :
                             "unavailable";
        addProtocolEvent(status, "Piece " + std::to_string(index) + " from " +
            endpointKey(peer.endpoint) + " failed: " + reason);
        return result;
    }
    const char *data = piece.data();
    std::size_t length = piece.size();
    Sha1 pieceHash;
    pieceHash.update(data, length);
    if (pieceHash.finalHex() != expectedHash) {
        recordPeerResult(peer, TransferResult::IntegrityFailure);
        recordDownloadFailure(status, TransferResult::IntegrityFailure);
        addProtocolEvent(status, "Piece " + std::to_string(index) + " from " +
            endpointKey(peer.endpoint) + " failed SHA1 verification");
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
    {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.destination = destination;
        status->telemetry.pieces.assign(
            metadata.pieceHashes.size(), PieceState::Unavailable);
        status->telemetry.availability.assign(metadata.pieceHashes.size(), 0);
        status->telemetry.lastSpeedSample = std::chrono::steady_clock::now();
        status->telemetry.events.push_back(
            "Metadata accepted: " + std::to_string(metadata.pieceHashes.size()) +
            " pieces from " + std::to_string(peers.size()) + " peers");
    }
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
    {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.lastSpeedBytes = resumedBytes;
        for (std::size_t piece = 0; piece < resumedPieces.size(); ++piece)
            if (resumedPieces[piece])
                status->telemetry.pieces[piece] = PieceState::Verified;
        if (status->completed)
            status->telemetry.events.push_back(
                "Resume validation retained " +
                std::to_string(status->completed.load()) + " pieces");
    }
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
    {
        std::lock_guard<std::mutex> reputationLock(reputationMutex);
        std::lock_guard<std::mutex> telemetryLock(status->telemetryMutex);
        status->telemetry.availability = rarity;
        status->telemetry.peers.clear();
        for (std::size_t index = 0; index < peers.size(); ++index) {
            const std::string endpoint = endpointKey(peers[index].endpoint);
            const PeerReputation &reputation = reputations[endpoint];
            PeerTelemetry peer;
            peer.endpoint = endpoint;
            peer.bitmap = peerBitmaps[index];
            peer.availablePieces = static_cast<std::size_t>(
                std::count(peer.bitmap.begin(), peer.bitmap.end(),
                           static_cast<unsigned char>(1)));
            peer.trust = std::max(0.0, std::min(100.0,
                100.0 - reputation.networkFailures * 2.0 -
                reputation.authenticationFailures * 20.0 -
                reputation.integrityFailures * 30.0));
            peer.throughputMiB = reputation.transferSeconds > 0.0
                ? static_cast<double>(reputation.bytes) / reputation.transferSeconds /
                  (1024.0 * 1024.0) : 0.0;
            peer.failures = reputation.networkFailures +
                            reputation.authenticationFailures +
                            reputation.integrityFailures;
            peer.blacklisted = reputation.blacklistedUntil > std::time(nullptr);
            status->telemetry.peers.push_back(std::move(peer));
        }
        for (std::size_t piece = 0; piece < rarity.size(); ++piece)
            if (!resumedPieces[piece])
                status->telemetry.pieces[piece] =
                    rarity[piece] ? PieceState::Available : PieceState::Unavailable;
    }
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
    {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.rarestQueue = order;
        status->telemetry.events.push_back(
            "Rarest-first queue built with " + std::to_string(order.size()) +
            " pending pieces");
    }

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
            if (piece < peerBitmaps[peer].size() && peerBitmaps[peer][piece] &&
                !peerBlacklisted(peers[peer]))
                candidates.push_back(peer);
        std::sort(candidates.begin(), candidates.end(), [&](std::size_t left, std::size_t right) {
            return reputationScore(peers[left]) > reputationScore(peers[right]);
        });
        if (candidates.size() > 1 &&
            std::abs(reputationScore(peers[candidates.front()]) -
                     reputationScore(peers[candidates.back()])) < 1.0)
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
    const std::size_t endgameCount = std::min<std::size_t>(3, missingCount);
    const std::size_t normalCount = missingCount - endgameCount;
    std::atomic<std::size_t> nextOrder{0};
    std::size_t workerCount = normalCount == 0 ? 0 : std::min<std::size_t>(
        8, std::max<std::size_t>(1, std::min(peers.size(), normalCount)));
    {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.workers.clear();
        for (std::size_t worker = 0; worker < workerCount; ++worker)
            status->telemetry.workers.push_back({worker + 1, std::nullopt, "", "idle"});
    }
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < workerCount; ++worker) {
        workers.emplace_back([&, worker] {
            for (;;) {
                if (status->cancelRequested) break;
                std::size_t position = nextOrder.fetch_add(1);
                if (position >= normalCount) break;
                std::size_t piece = order[position];
                bool obtained = false;
                {
                    std::lock_guard<std::mutex> lock(status->telemetryMutex);
                    status->telemetry.workers[worker].piece = piece;
                    status->telemetry.workers[worker].state = "reserved";
                    status->telemetry.pieces[piece] = PieceState::Reserved;
                }
                for (int round = 0;
                     round < 3 && !obtained && !status->cancelRequested; ++round) {
                    std::vector<std::size_t> candidates = candidatesFor(piece);
                    {
                        std::lock_guard<std::mutex> lock(status->telemetryMutex);
                        auto &reserved = status->telemetry.reservations[piece];
                        reserved.clear();
                        for (std::size_t peer : candidates)
                            reserved.push_back(endpointKey(peers[peer].endpoint));
                    }
                    for (std::size_t peer : candidates) {
                        if (status->cancelRequested) break;
                        const std::string selected = endpointKey(peers[peer].endpoint);
                        {
                            std::lock_guard<std::mutex> lock(status->telemetryMutex);
                            status->telemetry.workers[worker].peer = selected;
                            status->telemetry.workers[worker].state = "downloading";
                            status->telemetry.pieces[piece] = PieceState::Downloading;
                            status->telemetry.events.push_back(
                                "W" + std::to_string(worker + 1) + " requested piece " +
                                std::to_string(piece) + " from " + selected);
                            while (status->telemetry.events.size() > 80)
                                status->telemetry.events.pop_front();
                        }
                        auto transferStarted = std::chrono::steady_clock::now();
                        TransferResult result = fetchPiece(
                            peers[peer], group, name, metadata.capability, piece,
                            metadata.pieceHashes[piece], output, status);
                        double transferSeconds = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - transferStarted).count();
                        {
                            std::lock_guard<std::mutex> lock(status->telemetryMutex);
                            auto &workerStatus = status->telemetry.workers[worker];
                            workerStatus.transferSeconds += transferSeconds;
                            if (result == TransferResult::Success) {
                                ++workerStatus.completed;
                                workerStatus.bytes += std::min<u64>(
                                    PIECE_SIZE, metadata.size -
                                    static_cast<u64>(piece) * PIECE_SIZE);
                            } else {
                                ++workerStatus.failures;
                            }
                        }
                        if (result == TransferResult::IntegrityFailure)
                            ++status->integrityFailures;
                        if (result == TransferResult::Success) {
                            obtained = true;
                            markAvailable(piece);
                            ++status->completed;
                            sampleDownloadSpeed(status);
                            {
                                std::lock_guard<std::mutex> lock(status->telemetryMutex);
                                status->telemetry.pieces[piece] = PieceState::Verified;
                                status->telemetry.reservations.erase(piece);
                                status->telemetry.peerEndpointsUsed.insert(selected);
                                status->telemetry.peersUsed =
                                    status->telemetry.peerEndpointsUsed.size();
                                status->telemetry.events.push_back(
                                    "Piece " + std::to_string(piece) +
                                    " verified and committed");
                            }
                            break;
                        }
                    }
                    if (!obtained && !status->cancelRequested)
                        std::this_thread::sleep_for(retryDelay(round));
                }
                if (!obtained && !status->cancelRequested) {
                    failure = true;
                    std::lock_guard<std::mutex> lock(status->telemetryMutex);
                    status->telemetry.pieces[piece] = PieceState::Failed;
                    status->telemetry.reservations.erase(piece);
                }
            }
            std::lock_guard<std::mutex> lock(status->telemetryMutex);
            status->telemetry.workers[worker].piece.reset();
            status->telemetry.workers[worker].peer.clear();
            status->telemetry.workers[worker].state = "idle";
        });
    }
    for (auto &worker : workers) worker.join();
    if (status->cancelRequested) {
        close(output);
        finishDownload(status, true, "cancelled by user; resume data retained");
        return;
    }

    // Endgame mode duplicates the final few requests across the two best peers. The first
    // verified response wins, reducing tail latency from one slow or disconnected seeder.
    if (endgameCount) {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.workers.push_back(
            {workerCount + 1, std::nullopt, "", "endgame"});
    }
    for (std::size_t position = normalCount; position < missingCount; ++position) {
        if (status->cancelRequested) break;
        std::size_t piece = order[position];
        std::vector<std::size_t> candidates = candidatesFor(piece);
        if (candidates.empty()) {
            failure = true;
            std::lock_guard<std::mutex> lock(status->telemetryMutex);
            status->telemetry.pieces[piece] = PieceState::Failed;
            continue;
        }
        std::size_t requestCount = std::min<std::size_t>(2, candidates.size());
        if (requestCount > 1) status->duplicateRequests += requestCount - 1;
        {
            std::lock_guard<std::mutex> lock(status->telemetryMutex);
            auto &reserved = status->telemetry.reservations[piece];
            reserved.clear();
            for (std::size_t request = 0; request < requestCount; ++request)
                reserved.push_back(endpointKey(peers[candidates[request]].endpoint));
            status->telemetry.pieces[piece] = PieceState::Downloading;
            auto &worker = status->telemetry.workers.back();
            worker.piece = piece;
            worker.peer = requestCount > 1 ? "fastest of " + std::to_string(requestCount)
                                           : reserved.front();
            worker.state = "endgame";
            status->telemetry.events.push_back(
                "Endgame duplicated piece " + std::to_string(piece) +
                " across " + std::to_string(requestCount) + " peers");
        }
        struct EndgameState {
            std::mutex mutex;
            std::condition_variable condition;
            std::size_t completed = 0;
            bool won = false;
            std::string piece;
            std::string winner;
        };
        auto endgame = std::make_shared<EndgameState>();
        for (std::size_t request = 0; request < requestCount; ++request) {
            PeerInfo peer = peers[candidates[request]];
            std::string groupCopy = group, nameCopy = name;
            std::string capabilityCopy = metadata.capability;
            std::string expectedHash = metadata.pieceHashes[piece];
            std::string peerEndpoint = endpointKey(peer.endpoint);
            auto statusCopy = status;
            std::thread([endgame, peer, groupCopy, nameCopy, capabilityCopy, expectedHash,
                         statusCopy, piece, peerEndpoint] {
                std::string data;
                auto transferStarted = std::chrono::steady_clock::now();
                TransferResult result = fetchPieceData(
                    peer, groupCopy, nameCopy, capabilityCopy, piece, expectedHash,
                    data, statusCopy);
                double transferSeconds = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - transferStarted).count();
                if (result == TransferResult::IntegrityFailure)
                    ++statusCopy->integrityFailures;
                {
                    std::lock_guard<std::mutex> telemetryLock(
                        statusCopy->telemetryMutex);
                    auto &worker = statusCopy->telemetry.workers.back();
                    worker.transferSeconds += transferSeconds;
                    if (result != TransferResult::Success) ++worker.failures;
                }
                {
                    std::lock_guard<std::mutex> lock(endgame->mutex);
                    ++endgame->completed;
                    if (result == TransferResult::Success && !endgame->won) {
                        endgame->won = true;
                        endgame->piece = std::move(data);
                        endgame->winner = peerEndpoint;
                    }
                }
                endgame->condition.notify_one();
            }).detach();
        }
        {
            std::unique_lock<std::mutex> lock(endgame->mutex);
            endgame->condition.wait(lock, [&] {
                return endgame->won || endgame->completed == requestCount;
            });
            auto diskStarted = std::chrono::steady_clock::now();
            bool written = endgame->won && writePiece(output, piece, endgame->piece);
            status->diskMicroseconds += elapsedMicroseconds(diskStarted);
            if (written) {
                markAvailable(piece);
                ++status->completed;
                sampleDownloadSpeed(status);
                std::lock_guard<std::mutex> telemetryLock(status->telemetryMutex);
                status->telemetry.pieces[piece] = PieceState::Verified;
                status->telemetry.reservations.erase(piece);
                status->telemetry.peerEndpointsUsed.insert(endgame->winner);
                status->telemetry.peersUsed =
                    status->telemetry.peerEndpointsUsed.size();
                auto &worker = status->telemetry.workers.back();
                ++worker.completed;
                worker.bytes += std::min<u64>(
                    PIECE_SIZE, metadata.size - static_cast<u64>(piece) * PIECE_SIZE);
                status->telemetry.events.push_back(
                    "Piece " + std::to_string(piece) +
                    " won by " + endgame->winner + " and verified");
            } else {
                failure = true;
                std::lock_guard<std::mutex> telemetryLock(status->telemetryMutex);
                status->telemetry.pieces[piece] = PieceState::Failed;
                status->telemetry.reservations.erase(piece);
            }
        }
    }
    if (status->cancelRequested) {
        close(output);
        finishDownload(status, true, "cancelled by user; resume data retained");
        return;
    }
    if (endgameCount) {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        auto &worker = status->telemetry.workers.back();
        worker.piece.reset();
        worker.peer.clear();
        worker.state = failure ? "stopped" : "complete";
    }
    close(output);

    u64 verifiedSize = 0;
    std::string verifiedHash;
    std::vector<std::string> verifiedPieces;
    if (failure) {
        finishDownload(status, true, "one or more pieces could not be reconstructed");
        return;
    }
    addProtocolEvent(status, "Reconstruction complete; running full-file SHA1");
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
            std::thread(downloadFile, group, name, destination, metadata, peers, status).detach();
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
                       << " endgame-duplicates=" << status->duplicateRequests
                       << " integrity-failures=" << status->integrityFailures;
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
            std::lock_guard<std::mutex> lock(reputationMutex);
            if (reputations.empty()) {
                output << "No peer observations yet\n";
                return false;
            }
            for (const auto &entry : reputations) {
                const PeerReputation &reputation = entry.second;
                double throughput = reputation.transferSeconds > 0.0
                    ? static_cast<double>(reputation.bytes) / reputation.transferSeconds /
                      (1024.0 * 1024.0)
                    : 0.0;
                double trust = std::max(0.0, std::min(100.0,
                    100.0 - reputation.networkFailures * 2.0 -
                    reputation.authenticationFailures * 20.0 -
                    reputation.integrityFailures * 30.0));
                bool blacklisted = reputation.blacklistedUntil > std::time(nullptr);
                output << entry.first << " trust=" << std::fixed << std::setprecision(1)
                       << trust << " speed=" << throughput << "MiB/s"
                       << " ok=" << reputation.successes
                       << " network=" << reputation.networkFailures
                       << " auth=" << reputation.authenticationFailures
                       << " corrupt=" << reputation.integrityFailures
                       << " status=" << (blacklisted ? "BLACKLISTED" : "ACTIVE") << '\n';
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
                std::size_t blacklisted = 0;
                {
                    std::lock_guard<std::mutex> lock(reputationMutex);
                    for (const auto &peer : reputations)
                        if (peer.second.blacklistedUntil > std::time(nullptr)) ++blacklisted;
                }
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
                       << status->activeRequests << " requests active, "
                       << blacklisted << " blacklisted\n"
                       << "  scheduler: rare=" << status->rarePieces
                       << " resumed=" << status->resumedPieces
                       << " endgame-duplicates=" << status->duplicateRequests << '\n'
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

#ifdef TORRENT_ENABLE_FTXUI

static std::vector<DownloadView> captureDownloadViews() {
    std::vector<std::shared_ptr<DownloadStatus>> statuses;
    std::unordered_map<std::string, PeerReputation> reputationSnapshot;
    {
        std::lock_guard<std::mutex> lock(downloadsMutex);
        statuses = downloads;
    }
    {
        std::lock_guard<std::mutex> lock(reputationMutex);
        reputationSnapshot = reputations;
    }
    return buildDownloadViews(statuses, reputationSnapshot);
}

static void appendLog(std::deque<std::string> &log, const std::string &text) {
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty()) log.push_back(line);
    }
    while (log.size() > 100) log.pop_front();
}

static ftxui::Color stateColor(PieceState state) {
    const CatppuccinMocha &mocha = catppuccinMocha();
    switch (state) {
        case PieceState::Unavailable: return mocha.overlay;
        case PieceState::Available: return mocha.blue;
        case PieceState::Reserved: return mocha.yellow;
        case PieceState::Downloading: return mocha.peach;
        case PieceState::Verified: return mocha.green;
        case PieceState::Failed: return mocha.red;
    }
    return mocha.text;
}

static ftxui::Element pieceGrid(const DownloadView &view, int columns) {
    using namespace ftxui;
    const CatppuccinMocha &mocha = catppuccinMocha();
    Elements rows;
    Elements row;
    for (std::size_t index = 0; index < view.telemetry.pieces.size(); ++index) {
        PieceState state = view.telemetry.pieces[index];
        std::string glyph = state == PieceState::Verified ? "■" :
                            state == PieceState::Downloading ? "▼" :
                            state == PieceState::Reserved ? "◆" :
                            state == PieceState::Available ? "□" :
                            state == PieceState::Failed ? "!" : "·";
        row.push_back(text(glyph) | color(stateColor(state)));
        if (row.size() == static_cast<std::size_t>(columns)) {
            rows.push_back(hbox(std::move(row)));
            row.clear();
        }
    }
    if (!row.empty()) rows.push_back(hbox(std::move(row)));
    if (rows.empty())
        rows.push_back(text("No pieces (empty file)") | color(mocha.subtext));
    return vbox(std::move(rows));
}

static ftxui::Element speedGraph(const DownloadView &view, std::size_t maxColumns) {
    using namespace ftxui;
    const CatppuccinMocha &mocha = catppuccinMocha();
    static const char *levels[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    if (view.telemetry.speedHistory.empty())
        return text("waiting for samples") | color(mocha.subtext);
    double maximum = *std::max_element(
        view.telemetry.speedHistory.begin(), view.telemetry.speedHistory.end());
    maximum = std::max({0.01, maximum, viewSpeedMiB(view)});
    std::string graph;
    std::size_t first = view.telemetry.speedHistory.size() > maxColumns
        ? view.telemetry.speedHistory.size() - maxColumns : 0;
    for (std::size_t index = first;
         index < view.telemetry.speedHistory.size(); ++index) {
        double sample = view.telemetry.speedHistory[index];
        std::size_t level = std::min<std::size_t>(
            7, static_cast<std::size_t>(sample / maximum * 7.0));
        graph += levels[level];
    }
    std::ostringstream label;
    label << std::fixed << std::setprecision(2) << viewSpeedMiB(view)
          << " MiB/s avg  peak " << maximum;
    return vbox({text(graph) | color(mocha.blue),
                 text(label.str()) | color(mocha.subtext)});
}

static ftxui::Element completionModal(const DownloadView &view) {
    using namespace ftxui;
    const CatppuccinMocha &mocha = catppuccinMocha();
    double seconds = std::max(0.001, view.elapsedMicros / 1000000.0);
    double average = static_cast<double>(view.verifiedBytes) / seconds /
                     (1024.0 * 1024.0);
    std::ostringstream speed;
    speed << std::fixed << std::setprecision(2) << average << " MiB/s";
    Elements rows = {
        text(view.failed ? "TRANSFER FAILED" : "TRANSFER COMPLETE") |
            bold | color(view.failed ? mocha.red : mocha.green) | center,
        separator() | color(mocha.surface1),
        hbox({text("File          ") | color(mocha.subtext), text(view.name)}),
        hbox({text("Size          ") | color(mocha.subtext),
              text(formatBytes(view.totalBytes))}),
        hbox({text("Pieces        ") | color(mocha.subtext),
              text(std::to_string(view.completed) + "/" + std::to_string(view.total))}),
        hbox({text("Duration      ") | color(mocha.subtext),
              text(formatDuration(view.elapsedMicros))}),
        hbox({text("Average speed ") | color(mocha.subtext), text(speed.str())}),
        hbox({text("Peers used    ") | color(mocha.subtext),
              text(std::to_string(view.telemetry.peersUsed))}),
        hbox({text("Integrity     ") | color(mocha.subtext),
              text(view.telemetry.integrityVerified ? "SHA1 verified" : "not verified") |
                  color(view.telemetry.integrityVerified ? mocha.green : mocha.red)}),
        hbox({text("Destination   ") | color(mocha.subtext),
              text(view.telemetry.destination)}),
    };
    if (view.failed)
        rows.push_back(hbox({text("Reason        ") | color(mocha.subtext),
                            text(view.telemetry.failureReason) | color(mocha.red)}));
    rows.push_back(separator() | color(mocha.surface1));
    rows.push_back(text("Enter or Escape returns to the dashboard") |
                   color(mocha.subtext) | center);
    return themedPanel(" Result ", vbox(std::move(rows)), mocha.mantle) |
           size(ftxui::WIDTH, ftxui::GREATER_THAN, 64) | clear_under | center;
}

static int runTui() {
    using namespace ftxui;
    const CatppuccinMocha &mocha = catppuccinMocha();

    auto screen = ScreenInteractive::Fullscreen();
    std::string commandInput;
    std::deque<std::string> commandLog;
    std::vector<std::string> commandHistory;
    std::size_t historyCursor = 0;
    commandLog.push_back("Ready. Press : to enter a command.");
    std::size_t selected = 0;
    std::optional<std::size_t> summary;
    bool commandMode = false;
    bool help = false;
    std::atomic<bool> refreshing{true};
    std::size_t observedDownloadCount = 0;
    std::size_t eventScroll = 0;

    auto renderer = Renderer([&] {
        std::vector<DownloadView> views = captureDownloadViews();
        if (!views.empty()) selected = std::min(selected, views.size() - 1);
        else selected = 0;

        std::size_t trackerIndex;
        u64 currentSession;
        {
            std::lock_guard<std::mutex> lock(trackerMutex);
            trackerIndex = preferredTracker;
            currentSession = sessionId;
        }
        double aggregateSpeed = 0.0;
        for (const auto &view : views)
            if (!view.finished) aggregateSpeed += viewSpeedMiB(view);
        std::ostringstream aggregate;
        aggregate << views.size() << " transfers  ·  " << std::fixed
                  << std::setprecision(2) << aggregateSpeed << " MiB/s";
        Element header = vbox({
            hbox({
                text(" TORRENT ") | bold | bgcolor(mocha.blue) | color(mocha.crust),
                text("  secure swarm telemetry") | color(mocha.text),
                filler(),
                text(aggregate.str()) | color(mocha.blue) | bold,
                text("  ")
            }),
            hbox({
                text(" " + endpointKey(peerEndpoint)) | color(mocha.subtext),
                text("  tracker " + std::to_string(trackerIndex + 1)) |
                    color(mocha.subtext),
                text(currentSession ? "  authenticated" : "  signed out") |
                    color(currentSession ? mocha.green : mocha.yellow),
                filler(),
                text("↑↓ select   c cancel   : command   F1 help   F10 exit ") |
                    color(mocha.subtext)
            }),
            separator() | color(mocha.blue),
        }) | bgcolor(mocha.base);

        Elements transferRows;
        if (views.empty()) {
            transferRows.push_back(
                text("No downloads. Press : and run download file …") |
                    color(mocha.subtext));
        }
        for (std::size_t index = 0; index < views.size(); ++index) {
            const auto &view = views[index];
            std::string marker = view.failed ? "FAIL" : view.finished ? "DONE" : "LIVE";
            double progress = view.totalBytes
                ? static_cast<double>(view.verifiedBytes) / view.totalBytes
                : (view.finished && !view.failed ? 1.0 : 0.0);
            std::ostringstream line;
            line << (index == selected ? "› " : "  ") << marker << "  ["
                 << view.group << "] " << view.name << "  " << std::fixed
                 << std::setprecision(1) << progress * 100.0 << "%  "
                 << view.completed << "/" << view.total << "  "
                 << std::setprecision(2) << viewSpeedMiB(view) << " MiB/s";
            Element item = text(line.str()) |
                color(view.failed ? mocha.red :
                      view.finished ? mocha.green : mocha.text);
            if (index == selected)
                item = item | color(mocha.blue) | bgcolor(mocha.surface1) | focus;
            transferRows.push_back(item);
        }
        Element transferList = themedPanel(" Swarm transfers ",
            vbox(std::move(transferRows)) | frame, mocha.base) |
            size(HEIGHT, LESS_THAN, 7);

        Element details;
        if (views.empty()) {
            details = vbox({
                filler(),
                text("The dashboard will populate when a download starts.") |
                    center | color(mocha.subtext),
                filler(),
            });
        } else {
            const DownloadView &view = views[selected];
            double progress = view.totalBytes
                ? static_cast<double>(view.verifiedBytes) / view.totalBytes
                : (view.finished && !view.failed ? 1.0 : 0.0);
            std::ostringstream progressText;
            progressText << std::fixed << std::setprecision(1) << progress * 100.0
                         << "%  " << formatBytes(view.verifiedBytes) << " / "
                         << formatBytes(view.totalBytes) << "  ·  "
                         << view.completed << "/" << view.total << " pieces";
            Color progressColor = view.failed ? mocha.red :
                                  view.finished ? mocha.green : mocha.blue;
            Element torrentInfo = themedPanel(" Torrent information ", vbox({
                hbox({text(view.name) | bold, filler(),
                      text(view.telemetry.destination) | color(mocha.subtext)}),
                gauge(static_cast<float>(progress)) | color(progressColor),
                text(progressText.str()) | color(mocha.blue),
            }), mocha.base);

            std::size_t minAvailability = view.telemetry.availability.empty() ? 0 :
                *std::min_element(view.telemetry.availability.begin(),
                                  view.telemetry.availability.end());
            double averageAvailability = view.telemetry.availability.empty() ? 0.0 :
                static_cast<double>(std::accumulate(
                    view.telemetry.availability.begin(),
                    view.telemetry.availability.end(), std::size_t{0})) /
                view.telemetry.availability.size();
            std::ostringstream swarm;
            swarm << view.responsivePeers << "/" << view.discoveredPeers
                  << " responsive  ·  availability min " << minAvailability
                  << " avg " << std::fixed << std::setprecision(1)
                  << averageAvailability << "  ·  " << view.activeRequests
                  << " active";
            Element health = themedPanel(" Swarm health ",
                text(swarm.str()) | color(mocha.blue), mocha.mantle);

            Element legend = hbox({
                text("■ verified ") | color(stateColor(PieceState::Verified)),
                text("▼ active ") | color(stateColor(PieceState::Downloading)),
                text("◆ reserved ") | color(stateColor(PieceState::Reserved)),
                text("□ available ") | color(stateColor(PieceState::Available)),
                text("· unavailable ") | color(stateColor(PieceState::Unavailable)),
                text("! failed") | color(stateColor(PieceState::Failed)),
            });
            Element pieces = themedPanel(" Piece lifecycle ",
                vbox({pieceGrid(view, screen.dimx() >= 150 ? 48 : 32),
                      separator() | color(mocha.surface1), legend}), mocha.base);
            int dashboardWidth = std::max(40, screen.dimx());
            int leftWidth = dashboardWidth < 120 ? dashboardWidth :
                            std::max(60, dashboardWidth * 2 / 3);
            int rightWidth = std::max(40, dashboardWidth - leftWidth);
            std::size_t graphColumns = static_cast<std::size_t>(
                std::max(12, (leftWidth - 8) / 2));
            Element graph = themedPanel(
                " Rolling speed ", speedGraph(view, graphColumns), mocha.mantle);

            Elements peerRows = {
                hbox({text("endpoint") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 24),
                      text("pieces") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 9),
                      text("trust") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 8),
                      text("MiB/s") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 9),
                      text("state") | bold | color(mocha.mauve)})
            };
            for (const auto &peer : view.telemetry.peers) {
                std::ostringstream trust, speed;
                trust << std::fixed << std::setprecision(0) << peer.trust;
                speed << std::fixed << std::setprecision(2) << peer.throughputMiB;
                peerRows.push_back(hbox({
                    text(peer.endpoint) | size(WIDTH, EQUAL, 24),
                    text(std::to_string(peer.availablePieces) + "/" +
                         std::to_string(view.total)) | size(WIDTH, EQUAL, 9),
                    text(trust.str()) | size(WIDTH, EQUAL, 8),
                    text(speed.str()) | size(WIDTH, EQUAL, 9),
                    text(peer.blacklisted ? "blocked" : "active") |
                        color(peer.blacklisted ? mocha.red : mocha.green),
                }));
            }
            if (view.telemetry.peers.empty())
                peerRows.push_back(text("Waiting for peer bitmaps") |
                                   color(mocha.subtext));
            Element peersPanel = themedPanel(" Connected peers ",
                vbox(std::move(peerRows)) | frame, mocha.base);

            Elements queueRows;
            std::size_t queueShown = 0;
            for (std::size_t piece : view.telemetry.rarestQueue) {
                if (piece < view.telemetry.pieces.size() &&
                    view.telemetry.pieces[piece] == PieceState::Verified) continue;
                std::ostringstream row;
                std::size_t availability = piece < view.telemetry.availability.size()
                    ? view.telemetry.availability[piece] : 0;
                row << "#" << piece << "  availability " << availability;
                auto reservation = view.telemetry.reservations.find(piece);
                if (reservation != view.telemetry.reservations.end())
                    row << "  reserved ×" << reservation->second.size();
                queueRows.push_back(text(row.str()));
                if (++queueShown == 6) break;
            }
            if (queueRows.empty())
                queueRows.push_back(text("Queue drained") | color(mocha.green));
            Element scheduler = themedPanel(" Rarest-first scheduler ",
                vbox(std::move(queueRows)), mocha.mantle);

            Elements workerRows = {
                hbox({text("worker") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 7),
                      text("piece") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 7),
                      text("peer") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 20),
                      text("done") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 6),
                      text("fail") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 6),
                      text("MiB/s") | bold | color(mocha.mauve) |
                          size(WIDTH, EQUAL, 8),
                      text("state") | bold | color(mocha.mauve)})
            };
            for (const auto &worker : view.telemetry.workers) {
                double workerSpeed = worker.transferSeconds > 0.0
                    ? static_cast<double>(worker.bytes) / worker.transferSeconds /
                      (1024.0 * 1024.0) : 0.0;
                std::ostringstream workerSpeedText;
                workerSpeedText << std::fixed << std::setprecision(1) << workerSpeed;
                workerRows.push_back(hbox({
                    text("W" + std::to_string(worker.id)) | size(WIDTH, EQUAL, 7),
                    text(worker.piece ? std::to_string(*worker.piece) : "—") |
                        size(WIDTH, EQUAL, 7),
                    text(worker.peer.empty() ? "—" : worker.peer) |
                        size(WIDTH, EQUAL, 20),
                    text(std::to_string(worker.completed)) |
                        size(WIDTH, EQUAL, 6),
                    text(std::to_string(worker.failures)) |
                        size(WIDTH, EQUAL, 6),
                    text(workerSpeedText.str()) | size(WIDTH, EQUAL, 8),
                    text(worker.state) |
                        color(worker.state == "downloading" ||
                              worker.state == "endgame" ?
                              mocha.peach : mocha.subtext),
                }));
            }
            if (view.telemetry.workers.empty())
                workerRows.push_back(text("No active workers") |
                                     color(mocha.subtext));
            Element workersPanel = themedPanel(" Workers ",
                vbox(std::move(workerRows)), mocha.base);

            Elements eventRows;
            std::size_t eventCount = view.telemetry.events.size();
            std::size_t visibleEvents = 7;
            std::size_t maximumScroll = eventCount > visibleEvents
                ? eventCount - visibleEvents : 0;
            eventScroll = std::min(eventScroll, maximumScroll);
            std::size_t end = eventCount - eventScroll;
            std::size_t first = end > visibleEvents ? end - visibleEvents : 0;
            for (std::size_t i = first; i < end; ++i)
                eventRows.push_back(text("• " + view.telemetry.events[i]));
            if (eventRows.empty())
                eventRows.push_back(text("Waiting for protocol activity") |
                                    color(mocha.subtext));
            Element events = themedPanel(" Protocol events ",
                vbox(std::move(eventRows)), mocha.base);

            if (screen.dimx() < 120 || screen.dimy() < 35) {
                int halfWidth = std::max(20, dashboardWidth / 2);
                details = vbox({
                    torrentInfo,
                    hbox({
                        health | size(WIDTH, EQUAL, halfWidth),
                        graph | size(WIDTH, EQUAL, dashboardWidth - halfWidth),
                    }),
                    pieces,
                    events | flex,
                });
            } else {
                Element left = vbox({
                    torrentInfo,
                    hbox({
                        health | size(WIDTH, EQUAL, leftWidth / 2),
                        graph | size(WIDTH, EQUAL, leftWidth - leftWidth / 2),
                    }),
                    pieces | flex,
                    events | flex,
                }) | size(WIDTH, EQUAL, leftWidth);
                Element right = vbox({
                    peersPanel | flex,
                    scheduler | flex,
                    workersPanel | flex,
                }) | size(WIDTH, EQUAL, rightWidth);
                details = hbox({left, right});
            }
        }

        Elements activityRows;
        std::size_t activityFirst = commandLog.size() > 3 ? commandLog.size() - 3 : 0;
        for (std::size_t i = activityFirst; i < commandLog.size(); ++i) {
            bool error = commandLog[i].rfind("ERR", 0) == 0;
            activityRows.push_back(text(commandLog[i]) |
                                   color(error ? mocha.red : mocha.subtext));
        }
        Element activity = themedPanel(" Command activity ",
            vbox(std::move(activityRows)), mocha.mantle) |
            size(HEIGHT, LESS_THAN, 5);
        Element commandBar = commandMode
            ? hbox({text(" : ") | bold | color(mocha.mauve), text(commandInput),
                    text("█") | color(mocha.mauve), filler(),
                    text("Enter run · Esc cancel ") | color(mocha.subtext)})
            : hbox({text(" : command") | color(mocha.subtext), filler(),
                    text("FTXUI live view ") | color(mocha.blue)});
        commandBar = commandBar | color(mocha.text) | bgcolor(mocha.mantle);

        Element dashboard = vbox({
            header,
            transferList,
            details | flex,
            activity,
            separator() | color(mocha.surface1),
            commandBar,
        }) | color(mocha.text) | bgcolor(mocha.crust);

        if (help) {
            Element helpModal = themedPanel(" Keyboard and commands ", vbox({
                text("↑ ↓ ← →   select a download / command history"),
                text("PgUp/PgDn  scroll protocol events"),
                text("c           cancel selected active download"),
                text(":           open command bar"),
                text("Enter       execute command / close result"),
                text("Escape      close command bar, help, or result"),
                text("F1          toggle this help"),
                text("F10         exit"),
                separator() | color(mocha.surface1),
                text("The command bar accepts every classic CLI command.") |
                    color(mocha.subtext),
                text("Passwords are masked in command activity history.") |
                    color(mocha.subtext),
            }), mocha.mantle) |
                size(WIDTH, GREATER_THAN, 62) | clear_under | center;
            dashboard = dbox({dashboard, helpModal});
        } else if (summary && *summary < views.size()) {
            dashboard = dbox({dashboard, completionModal(views[*summary])});
        }
        return dashboard;
    });

    auto runCommand = [&](std::string line) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty() && line.front() == ':') line.erase(line.begin());
        std::size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) return false;
        line.erase(0, first);
        commandLog.push_back("> " + safeCommandForLog(line));
        if (!commandContainsPassword(line) &&
            (commandHistory.empty() || commandHistory.back() != line))
            commandHistory.push_back(line);
        historyCursor = commandHistory.size();
        std::ostringstream output;
        bool quit = executeCommand(line, output);
        appendLog(commandLog, output.str());
        if (commandContainsPassword(line)) secureErase(line);
        if (quit) {
            refreshing = false;
            screen.ExitLoopClosure()();
        }
        return quit;
    };

    auto component = CatchEvent(renderer, [&](Event event) {
        if (event == Event::F10) {
            refreshing = false;
            screen.ExitLoopClosure()();
            return true;
        }
        if (event == Event::Custom) {
            std::vector<std::shared_ptr<DownloadStatus>> statuses;
            {
                std::lock_guard<std::mutex> lock(downloadsMutex);
                statuses = downloads;
            }
            if (statuses.size() > observedDownloadCount) {
                selected = statuses.size() - 1;
                eventScroll = 0;
                observedDownloadCount = statuses.size();
            } else if (statuses.size() < observedDownloadCount) {
                observedDownloadCount = statuses.size();
            }
            for (std::size_t index = 0; index < statuses.size(); ++index) {
                if (statuses[index]->finished &&
                    !statuses[index]->summaryPresented.exchange(true)) {
                    selected = index;
                    summary = index;
                    commandMode = false;
                    help = false;
                    break;
                }
            }
            return true;
        }
        if (summary) {
            if (event == Event::Return || event == Event::Escape) {
                summary.reset();
                return true;
            }
            return true;
        }
        if (help) {
            if (event == Event::F1 || event == Event::Escape ||
                event == Event::Return) {
                help = false;
                return true;
            }
            return true;
        }
        if (event == Event::F1) {
            help = true;
            commandMode = false;
            return true;
        }
        if (commandMode) {
            if (event == Event::Escape) {
                commandMode = false;
                commandInput.clear();
                return true;
            }
            if (event == Event::Backspace) {
                if (!commandInput.empty()) commandInput.pop_back();
                return true;
            }
            if (event == Event::ArrowUp) {
                if (!commandHistory.empty() && historyCursor > 0) {
                    --historyCursor;
                    commandInput = commandHistory[historyCursor];
                }
                return true;
            }
            if (event == Event::ArrowDown) {
                if (historyCursor + 1 < commandHistory.size()) {
                    ++historyCursor;
                    commandInput = commandHistory[historyCursor];
                } else {
                    historyCursor = commandHistory.size();
                    commandInput.clear();
                }
                return true;
            }
            if (event == Event::Return) {
                if (commandInput.empty()) {
                    commandMode = false;
                    return true;
                }
                runCommand(commandInput);
                if (commandContainsPassword(commandInput))
                    secureErase(commandInput);
                else
                    commandInput.clear();
                return true;
            }
            if (event.is_character()) {
                std::string pasted = event.character();
                commandInput += pasted;
                for (;;) {
                    std::size_t newline = commandInput.find_first_of("\r\n");
                    if (newline == std::string::npos) break;
                    std::string line = commandInput.substr(0, newline);
                    std::size_t consumed = newline + 1;
                    if (commandInput[newline] == '\r' &&
                        consumed < commandInput.size() &&
                        commandInput[consumed] == '\n')
                        ++consumed;
                    commandInput.erase(0, consumed);
                    if (runCommand(std::move(line))) {
                        commandInput.clear();
                        return true;
                    }
                }
                return true;
            }
            return true;
        }
        if (event == Event::Character(":")) {
            commandMode = true;
            commandInput.clear();
            historyCursor = commandHistory.size();
            return true;
        }
        if (event == Event::Character("c")) {
            std::lock_guard<std::mutex> lock(downloadsMutex);
            if (selected < downloads.size() && !downloads[selected]->finished) {
                downloads[selected]->cancelRequested = true;
                commandLog.push_back("Cancellation requested for " +
                                     downloads[selected]->name);
            }
            return true;
        }
        if (event == Event::PageUp) {
            eventScroll += 6;
            return true;
        }
        if (event == Event::PageDown) {
            eventScroll = eventScroll > 6 ? eventScroll - 6 : 0;
            return true;
        }
        if (event == Event::ArrowUp || event == Event::ArrowLeft) {
            if (selected > 0) {
                --selected;
                eventScroll = 0;
            }
            return true;
        }
        if (event == Event::ArrowDown || event == Event::ArrowRight) {
            std::lock_guard<std::mutex> lock(downloadsMutex);
            if (selected + 1 < downloads.size()) {
                ++selected;
                eventScroll = 0;
            }
            return true;
        }
        return false;
    });

    std::thread refresher([&] {
        while (refreshing) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (refreshing) screen.PostEvent(Event::Custom);
        }
    });
    screen.Loop(component);
    refreshing = false;
    refresher.join();
    return 0;
}

#else

static int runTui() {
    std::cerr << "This binary was built without FTXUI support. "
                 "Use the CMake build for --tui.\n";
    return 1;
}

#endif

static int runCli() {
    std::cout << "Client listening on " << peerEndpoint.ip << ':' << peerEndpoint.port << '\n';
    std::string line;
    while (std::cout << "> " && std::getline(std::cin, line)) {
        if (executeCommand(line, std::cout)) break;
    }
    return 0;
}

int main(int argc, char **argv) {
    bool tui = argc == 4 && std::string(argv[3]) == "--tui";
    if ((argc != 3 && !tui) || !parseEndpoint(argv[1], peerEndpoint) ||
        !loadTrackerInfo(argv[2], trackers)) {
        std::cerr << "usage: " << argv[0]
                  << " <peer-ip:port> tracker_info.txt [--tui]\n";
        return 1;
    }
    std::thread(peerServer).detach();
    return tui ? runTui() : runCli();
}

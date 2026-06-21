#include "../common/protocol.hpp"
#include "../common/sha1.hpp"
#include "../common/elgamal.hpp"

#include <atomic>
#include <chrono>
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

struct Endpoint {
    std::string ip;
    int port = 0;
};

struct LocalFile {
    std::string path;
    u64 size = 0;
    std::string fullHash;
    std::string capability;
    std::vector<std::string> pieceHashes;
    std::vector<unsigned char> available;
};

struct PeerInfo {
    Endpoint endpoint;
    std::string publicKey;
};

enum class PieceState {
    Unavailable,
    Available,
    Reserved,
    Downloading,
    Verified,
    Failed
};

struct PeerTelemetry {
    std::string endpoint;
    std::vector<unsigned char> bitmap;
    std::size_t availablePieces = 0;
    double trust = 100.0;
    double throughputMiB = 0.0;
    u64 failures = 0;
    bool blacklisted = false;
};

struct WorkerTelemetry {
    std::size_t id = 0;
    std::optional<std::size_t> piece;
    std::string peer;
    std::string state = "idle";
    std::size_t completed = 0;
    std::size_t failures = 0;
    u64 bytes = 0;
    double transferSeconds = 0.0;
};

struct DownloadTelemetry {
    std::vector<PieceState> pieces;
    std::vector<std::size_t> availability;
    std::vector<std::size_t> rarestQueue;
    std::map<std::size_t, std::vector<std::string>> reservations;
    std::vector<PeerTelemetry> peers;
    std::vector<WorkerTelemetry> workers;
    std::deque<std::string> events;
    std::deque<double> speedHistory;
    std::string destination;
    std::string failureReason;
    bool integrityVerified = false;
    std::size_t peersUsed = 0;
    std::set<std::string> peerEndpointsUsed;
    u64 lastSpeedBytes = 0;
    std::chrono::steady_clock::time_point lastSpeedSample =
        std::chrono::steady_clock::now();
};

struct DownloadStatus {
    std::string group;
    std::string name;
    std::atomic<std::size_t> completed{0};
    std::size_t total = 0;
    std::atomic<bool> finished{false};
    std::atomic<bool> failed{false};
    std::atomic<std::size_t> duplicateRequests{0};
    std::atomic<std::size_t> integrityFailures{0};
    std::atomic<std::size_t> rarePieces{0};
    std::atomic<std::size_t> resumedPieces{0};
    std::atomic<u64> totalBytes{0};
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    std::atomic<u64> verifiedBytes{0};
    std::atomic<u64> resumedVerifiedBytes{0};
    std::atomic<u64> wireRequests{0};
    std::atomic<u64> retries{0};
    std::atomic<u64> networkFailures{0};
    std::atomic<u64> authenticationFailures{0};
    std::atomic<u64> unavailableResponses{0};
    std::atomic<u64> activeRequests{0};
    std::atomic<u64> cryptoMicroseconds{0};
    std::atomic<u64> networkMicroseconds{0};
    std::atomic<u64> diskMicroseconds{0};
    std::atomic<std::size_t> discoveredPeers{0};
    std::atomic<std::size_t> responsivePeers{0};
    std::atomic<u64> finalElapsedMicroseconds{0};
    mutable std::mutex telemetryMutex;
    DownloadTelemetry telemetry;
    std::atomic<bool> summaryPresented{false};
};

struct PeerReputation {
    u64 successes = 0;
    u64 networkFailures = 0;
    u64 authenticationFailures = 0;
    u64 integrityFailures = 0;
    u64 bytes = 0;
    double transferSeconds = 0.0;
    std::time_t blacklistedUntil = 0;
};

struct ResumeState {
    std::mutex mutex;
    std::string manifestPath;
    std::string temporaryPath;
    std::string group;
    std::string name;
    LocalFile metadata;
    std::vector<unsigned char> verified;
};

enum class TransferResult {
    Success,
    NetworkFailure,
    AuthenticationFailure,
    IntegrityFailure,
    Unavailable
};

static u64 elapsedMicroseconds(std::chrono::steady_clock::time_point started) {
    return static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count());
}

static void recordDownloadFailure(const std::shared_ptr<DownloadStatus> &status,
                                  TransferResult result) {
    if (!status || result == TransferResult::Success) return;
    ++status->retries;
    if (result == TransferResult::NetworkFailure) ++status->networkFailures;
    else if (result == TransferResult::AuthenticationFailure)
        ++status->authenticationFailures;
    else if (result == TransferResult::Unavailable) ++status->unavailableResponses;
}

static void addProtocolEvent(const std::shared_ptr<DownloadStatus> &status,
                             const std::string &event) {
    if (!status) return;
    std::lock_guard<std::mutex> lock(status->telemetryMutex);
    status->telemetry.events.push_back(event);
    while (status->telemetry.events.size() > 80)
        status->telemetry.events.pop_front();
}

static void sampleDownloadSpeed(const std::shared_ptr<DownloadStatus> &status,
                                bool force = false) {
    if (!status) return;
    std::lock_guard<std::mutex> lock(status->telemetryMutex);
    auto now = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration<double>(
        now - status->telemetry.lastSpeedSample).count();
    if (!force && seconds < 0.25) return;
    u64 bytes = status->verifiedBytes.load();
    u64 delta = bytes >= status->telemetry.lastSpeedBytes
        ? bytes - status->telemetry.lastSpeedBytes : 0;
    status->telemetry.speedHistory.push_back(
        seconds > 0.0 ? static_cast<double>(delta) / seconds / (1024.0 * 1024.0) : 0.0);
    while (status->telemetry.speedHistory.size() > 60)
        status->telemetry.speedHistory.pop_front();
    status->telemetry.lastSpeedBytes = bytes;
    status->telemetry.lastSpeedSample = now;
}

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
static ElGamalKey peerKey;
static std::mutex replayMutex;
static std::unordered_map<std::string, std::time_t> seenNonces;
static std::mutex reputationMutex;
static std::unordered_map<std::string, PeerReputation> reputations;

static std::string joinHashes(const std::vector<std::string> &hashes);

static bool saveResumeLocked(const ResumeState &resume) {
    std::string temporaryManifest = resume.manifestPath + ".tmp";
    std::ofstream output(temporaryManifest, std::ios::trunc);
    if (!output) return false;
    output << "P2PRESUME1\n"
           << hexEncode(resume.group) << '\n'
           << hexEncode(resume.name) << '\n'
           << resume.metadata.size << '\n'
           << resume.metadata.fullHash << '\n'
           << resume.metadata.capability << '\n'
           << joinHashes(resume.metadata.pieceHashes) << '\n';
    for (unsigned char piece : resume.verified) output << (piece ? '1' : '0');
    output << '\n' << hexEncode(resume.temporaryPath) << '\n';
    output.flush();
    if (!output) return false;
    output.close();
    chmod(temporaryManifest.c_str(), 0600);
    if (rename(temporaryManifest.c_str(), resume.manifestPath.c_str()) != 0) return false;
    chmod(resume.manifestPath.c_str(), 0600);
    return true;
}

static bool loadResume(const std::string &manifestPath, const std::string &group,
                       const std::string &name, const LocalFile &metadata,
                       std::string &temporaryPath, std::vector<unsigned char> &verified) {
    std::ifstream input(manifestPath);
    std::string version, encodedGroup, encodedName, sizeText, fullHash;
    std::string capability, hashes, bitmap, encodedTemporary;
    if (!std::getline(input, version) || !std::getline(input, encodedGroup) ||
        !std::getline(input, encodedName) || !std::getline(input, sizeText) ||
        !std::getline(input, fullHash) || !std::getline(input, capability) ||
        !std::getline(input, hashes) || !std::getline(input, bitmap) ||
        !std::getline(input, encodedTemporary) || version != "P2PRESUME1")
        return false;
    std::string storedGroup, storedName;
    u64 storedSize = 0;
    try { storedSize = static_cast<u64>(std::stoull(sizeText)); } catch (...) { return false; }
    if (!hexDecode(encodedGroup, storedGroup) || !hexDecode(encodedName, storedName) ||
        !hexDecode(encodedTemporary, temporaryPath) || storedGroup != group ||
        storedName != name || storedSize != metadata.size ||
        fullHash != metadata.fullHash || capability != metadata.capability ||
        hashes != joinHashes(metadata.pieceHashes) ||
        bitmap.size() != metadata.pieceHashes.size())
        return false;
    verified.resize(bitmap.size());
    for (std::size_t i = 0; i < bitmap.size(); ++i) {
        if (bitmap[i] != '0' && bitmap[i] != '1') return false;
        verified[i] = bitmap[i] == '1';
    }
    return true;
}

static bool verifyStoredPieces(int fd, const LocalFile &metadata,
                               std::vector<unsigned char> &verified) {
    std::vector<char> buffer(PIECE_SIZE);
    for (std::size_t piece = 0; piece < verified.size(); ++piece) {
        if (!verified[piece]) continue;
        std::size_t expected = static_cast<std::size_t>(
            std::min<u64>(PIECE_SIZE, metadata.size - static_cast<u64>(piece) * PIECE_SIZE));
        std::size_t received = 0;
        off_t offset = static_cast<off_t>(piece * PIECE_SIZE);
        while (received < expected) {
            ssize_t count = pread(fd, buffer.data() + received, expected - received,
                                  offset + static_cast<off_t>(received));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            received += static_cast<std::size_t>(count);
        }
        Sha1 hash;
        hash.update(buffer.data(), received);
        if (received != expected || hash.finalHex() != metadata.pieceHashes[piece])
            verified[piece] = 0;
    }
    return true;
}

static std::string endpointKey(const Endpoint &endpoint) {
    return endpoint.ip + ":" + std::to_string(endpoint.port);
}

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

static std::string baseName(const std::string &path) {
    std::size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

static bool parseEndpoint(const std::string &text, Endpoint &endpoint) {
    std::size_t colon = text.rfind(':');
    if (colon == std::string::npos) return false;
    endpoint.ip = text.substr(0, colon);
    try { endpoint.port = std::stoi(text.substr(colon + 1)); } catch (...) { return false; }
    return !endpoint.ip.empty() && endpoint.port > 0 && endpoint.port <= 65535;
}

static bool readTrackerInfo(const std::string &path) {
    std::ifstream input(path);
    if (!input) return false;
    std::string token;
    while (input >> token) {
        Endpoint endpoint;
        if (token.find(':') != std::string::npos) {
            if (!parseEndpoint(token, endpoint)) return false;
        } else {
            endpoint.ip = token;
            if (!(input >> endpoint.port)) return false;
        }
        trackers.push_back(endpoint);
    }
    return trackers.size() == 2;
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

static bool hashFile(const std::string &path, u64 &size, std::string &fullHash,
                     std::vector<std::string> &pieceHashes) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    Sha1 complete;
    std::vector<char> buffer(PIECE_SIZE);
    size = 0;
    pieceHashes.clear();
    for (;;) {
        std::size_t used = 0;
        while (used < buffer.size()) {
            ssize_t count = read(fd, buffer.data() + used, buffer.size() - used);
            if (count < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return false;
            }
            if (count == 0) break;
            used += static_cast<std::size_t>(count);
        }
        if (used == 0) break;
        Sha1 piece;
        piece.update(buffer.data(), used);
        pieceHashes.push_back(piece.finalHex());
        complete.update(buffer.data(), used);
        size += used;
        if (used < buffer.size()) break;
    }
    close(fd);
    fullHash = complete.finalHex();
    return true;
}

static std::string joinHashes(const std::vector<std::string> &hashes) {
    if (hashes.empty()) return "-";
    std::string result;
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        if (i) result.push_back(',');
        result += hashes[i];
    }
    return result;
}

static std::string uploadCommand(const std::string &group, const std::string &name,
                                 const LocalFile &file) {
    return "upload_file " + group + " " + hexEncode(name) + " " +
           std::to_string(file.size) + " " + file.fullHash + " " + file.capability + " " +
           joinHashes(file.pieceHashes) + " " + peerEndpoint.ip + " " +
           std::to_string(peerEndpoint.port) + " " + peerKey.publicHex();
}

static void peerConnection(int fd) {
    timeval timeout{};
    timeout.tv_sec = 8;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string hello;
    if (!receiveFrame(fd, hello)) {
        close(fd);
        return;
    }
    std::vector<std::string> helloFields = split(hello, '|');
    if (helloFields.size() != 7 || helloFields[0] != "20") {
        sendFrame(fd, "60|malformed");
        close(fd);
        return;
    }
    std::time_t timestamp = 0;
    try { timestamp = static_cast<std::time_t>(std::stoll(helloFields[1])); }
    catch (...) { sendFrame(fd, "60|timestamp"); close(fd); return; }
    std::time_t now = std::time(nullptr);
    if (timestamp < now - 60 || timestamp > now + 60) {
        sendFrame(fd, "60|stale");
        close(fd);
        return;
    }
    std::string clientNonce;
    if (!hexDecode(helloFields[2], clientNonce) || clientNonce.size() != 16) {
        sendFrame(fd, "60|encoding"); close(fd); return;
    }
    std::string helloHeader = helloFields[0] + "|" + helloFields[1] + "|" + helloFields[2] +
                              "|" + helloFields[3] + "|" + helloFields[4];
    if (!peerKey.verify(sha256(helloHeader), {helloFields[5], helloFields[6]},
                        helloFields[4])) {
        sendFrame(fd, "60|signature"); close(fd); return;
    }
    {
        std::lock_guard<std::mutex> lock(replayMutex);
        for (auto it = seenNonces.begin(); it != seenNonces.end();) {
            if (it->second < now - 120) it = seenNonces.erase(it); else ++it;
        }
        if (seenNonces.count(helloFields[2])) {
            sendFrame(fd, "60|replay"); close(fd); return;
        }
        seenNonces[helloFields[2]] = timestamp;
    }

    std::string serverPrivate, serverEphemeral, serverNonce = randomBytes(16), sharedSecret;
    if (serverNonce.empty() ||
        !peerKey.generateEphemeral(serverPrivate, serverEphemeral) ||
        !peerKey.deriveEphemeralSecret(serverPrivate, helloFields[3], sharedSecret)) {
        sendFrame(fd, "60|key"); close(fd); return;
    }
    std::string transcript = helloHeader + "|" + hexEncode(serverNonce) + "|" +
                             serverEphemeral + "|" + peerKey.publicHex();
    ElGamalSignature serverProof = peerKey.sign(sha256(transcript));
    std::string helloResponse = "25|" + hexEncode(serverNonce) + "|" + serverEphemeral + "|" +
                                peerKey.publicHex() + "|" + serverProof.r + "|" + serverProof.s;
    if (!sendFrame(fd, helloResponse)) { close(fd); return; }

    // Ephemeral private material is no longer needed after deriving the shared secret.
    secureErase(serverPrivate);
    std::string sessionKey = sha256(sharedSecret + transcript);
    secureErase(sharedSecret);
    std::string encryptionKey = sha256(sessionKey + "ENC");
    std::string macKey = sha256(sessionKey + "MAC");

    std::string request;
    if (!receiveFrame(fd, request)) { close(fd); return; }
    std::vector<std::string> fields = split(request, '|');
    if (fields.size() != 4 || fields[0] != "21") {
        sendFrame(fd, "60|request"); close(fd); return;
    }
    std::string requestIv, requestCipher, requestTag;
    if (!hexDecode(fields[1], requestIv) || requestIv.size() != 16 ||
        !hexDecode(fields[2], requestCipher) || !hexDecode(fields[3], requestTag)) {
        sendFrame(fd, "60|encoding"); close(fd); return;
    }
    std::string authenticated = fields[0] + "|" + fields[1] + "|" + fields[2];
    if (!constantTimeEqual(hmacSha256(macKey, authenticated), requestTag)) {
        sendFrame(fd, "60|hmac"); close(fd); return;
    }
    std::string requestPlain;
    if (!aes256CbcDecrypt(encryptionKey, requestIv, requestCipher, requestPlain)) {
        sendFrame(fd, "60|decrypt"); close(fd); return;
    }
    std::vector<std::string> requestParts = split(requestPlain, '\n');
    if (requestParts.size() != 5) { sendFrame(fd, "60|request"); close(fd); return; }
    std::string operation = requestParts[0], group = requestParts[1];
    std::string name = requestParts[2], capability = requestParts[4];
    std::size_t pieceIndex = 0;
    try { pieceIndex = static_cast<std::size_t>(std::stoull(requestParts[3])); }
    catch (...) { sendFrame(fd, "60|piece"); close(fd); return; }
    LocalFile file;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(sharedMutex);
        auto it = sharedFiles.find(keyFor(group, name));
        if (it != sharedFiles.end() && constantTimeEqual(it->second.capability, capability) &&
            (operation == "BITMAP" ||
             (operation == "GET" && pieceIndex < it->second.pieceHashes.size() &&
              pieceIndex < it->second.available.size() && it->second.available[pieceIndex]))) {
            file = it->second;
            found = true;
        }
    }
    if (!found) {
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
    {
        std::string responseNonce = randomBytes(16), responseIv = randomBytes(16);
        std::string responseCipher = aes256CbcEncrypt(encryptionKey, responseIv, responsePlain);
        ElGamalSignature signature = peerKey.sign(
            sha256(helloFields[2] + "|" + hexEncode(responseNonce) + "|" + sha256(responseCipher)));
        std::string responseHeader = "30|" + hexEncode(responseNonce) + "|" + signature.r + "|" +
                                     signature.s + "|" + hexEncode(responseIv) + "|" +
                                     hexEncode(responseCipher);
        sendFrame(fd, responseHeader + "|" + hexEncode(hmacSha256(macKey, responseHeader)));
    }
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

static TransferResult securePeerRequest(const PeerInfo &peer, const std::string &plain,
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
    std::string clientPrivate, clientEphemeral, clientNonce = randomBytes(16);
    auto cryptoStarted = std::chrono::steady_clock::now();
    bool ephemeralReady = !clientNonce.empty() &&
                          peerKey.generateEphemeral(clientPrivate, clientEphemeral);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!ephemeralReady) {
        close(fd);
        return TransferResult::NetworkFailure;
    }
    std::string helloHeader = "20|" + std::to_string(std::time(nullptr)) + "|" +
                              hexEncode(clientNonce) + "|" + clientEphemeral + "|" +
                              peerKey.publicHex();
    cryptoStarted = std::chrono::steady_clock::now();
    ElGamalSignature clientProof = peerKey.sign(sha256(helloHeader));
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    std::string hello = helloHeader + "|" + clientProof.r + "|" + clientProof.s;
    std::string helloResponse;
    if (!sendFrame(fd, hello) || !receiveFrame(fd, helloResponse)) {
        close(fd);
        return TransferResult::NetworkFailure;
    }
    std::vector<std::string> helloFields = split(helloResponse, '|');
    if (helloFields.size() != 6 || helloFields[0] != "25" ||
        helloFields[3] != peer.publicKey) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    std::string serverNonce;
    if (!hexDecode(helloFields[1], serverNonce) || serverNonce.size() != 16) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    std::string transcript = helloHeader + "|" + helloFields[1] + "|" +
                             helloFields[2] + "|" + helloFields[3];
    cryptoStarted = std::chrono::steady_clock::now();
    bool serverVerified = peerKey.verify(
        sha256(transcript), {helloFields[4], helloFields[5]}, peer.publicKey);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!serverVerified) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    std::string sharedSecret;
    cryptoStarted = std::chrono::steady_clock::now();
    bool secretReady = peerKey.deriveEphemeralSecret(
        clientPrivate, helloFields[2], sharedSecret);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!secretReady) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    secureErase(clientPrivate);
    std::string sessionKey = sha256(sharedSecret + transcript);
    secureErase(sharedSecret);
    std::string encryptionKey = sha256(sessionKey + "ENC");
    std::string macKey = sha256(sessionKey + "MAC");
    std::string iv = randomBytes(16);
    if (iv.empty()) { close(fd); return TransferResult::NetworkFailure; }
    cryptoStarted = std::chrono::steady_clock::now();
    std::string cipher = aes256CbcEncrypt(encryptionKey, iv, plain);
    std::string requestHeader = "21|" + hexEncode(iv) + "|" + hexEncode(cipher);
    std::string request = requestHeader + "|" + hexEncode(hmacSha256(macKey, requestHeader));
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    std::string response;
    bool ok = sendFrame(fd, request) && receiveFrame(fd, response);
    close(fd);
    seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (!ok) return TransferResult::NetworkFailure;
    std::vector<std::string> fields = split(response, '|');
    if (fields.size() >= 2 && fields[0] == "60") {
        if (fields[1] == "unauthorized" || fields[1] == "hmac" || fields[1] == "key" ||
            fields[1] == "replay" || fields[1] == "stale" || fields[1] == "signature")
            return TransferResult::AuthenticationFailure;
        return TransferResult::Unavailable;
    }
    if (fields.size() != 7 || fields[0] != "30")
        return TransferResult::AuthenticationFailure;
    std::string responseNonce, responseIv, responseCipher, responseTag;
    if (!hexDecode(fields[1], responseNonce) || responseNonce.size()!=16 ||
        !hexDecode(fields[4], responseIv) || responseIv.size()!=16 ||
        !hexDecode(fields[5], responseCipher) || !hexDecode(fields[6], responseTag))
        return TransferResult::AuthenticationFailure;
    std::string responseHeader = fields[0]+"|"+fields[1]+"|"+fields[2]+"|"+fields[3]+"|"+fields[4]+"|"+fields[5];
    cryptoStarted = std::chrono::steady_clock::now();
    bool responseMacValid = constantTimeEqual(
        hmacSha256(macKey, responseHeader), responseTag);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!responseMacValid)
        return TransferResult::AuthenticationFailure;
    cryptoStarted = std::chrono::steady_clock::now();
    bool responseSignatureValid = peerKey.verify(
        sha256(hexEncode(clientNonce)+"|"+fields[1]+"|"+sha256(responseCipher)),
        {fields[2], fields[3]}, peer.publicKey);
    telemetry.crypto += elapsedMicroseconds(cryptoStarted);
    if (!responseSignatureValid)
        return TransferResult::AuthenticationFailure;
    cryptoStarted = std::chrono::steady_clock::now();
    bool decrypted = aes256CbcDecrypt(
        encryptionKey, responseIv, responseCipher, responsePlain);
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
        peer, "GET\n" + group + "\n" + name + "\n" + std::to_string(index) + "\n" + capability,
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

static bool writePiece(int outputFd, std::size_t index, const std::string &piece) {
    std::size_t written = 0;
    off_t offset = static_cast<off_t>(index * PIECE_SIZE);
    while (written < piece.size()) {
        ssize_t count = pwrite(outputFd, piece.data() + written, piece.size() - written,
                               offset + static_cast<off_t>(written));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return true;
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
        peer, "BITMAP\n" + group + "\n" + name + "\n0\n" + capability,
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
                for (int round = 0; round < 2 && !obtained; ++round) {
                    std::vector<std::size_t> candidates = candidatesFor(piece);
                    {
                        std::lock_guard<std::mutex> lock(status->telemetryMutex);
                        auto &reserved = status->telemetry.reservations[piece];
                        reserved.clear();
                        for (std::size_t peer : candidates)
                            reserved.push_back(endpointKey(peers[peer].endpoint));
                    }
                    for (std::size_t peer : candidates) {
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
                    if (!obtained) std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                if (!obtained) {
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

    // Endgame mode duplicates the final few requests across the two best peers. The first
    // verified response wins, reducing tail latency from one slow or disconnected seeder.
    if (endgameCount) {
        std::lock_guard<std::mutex> lock(status->telemetryMutex);
        status->telemetry.workers.push_back(
            {workerCount + 1, std::nullopt, "", "endgame"});
    }
    for (std::size_t position = normalCount; position < missingCount; ++position) {
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

static std::vector<std::string> words(const std::string &line) {
    std::istringstream input(line);
    std::vector<std::string> result;
    std::string word;
    while (input >> word) result.push_back(word);
    return result;
}

static std::string canonicalCommand(const std::vector<std::string> &args) {
    if (args.empty()) return "";
    if (args[0].find('_') != std::string::npos || args.size() == 1) return args[0];
    if ((args[0] == "create" || args[0] == "join" || args[0] == "leave" ||
         args[0] == "list" || args[0] == "accept" || args[0] == "upload" ||
         args[0] == "download" || args[0] == "stop" || args[0] == "show") &&
        args.size() >= 2)
        return args[0] + "_" + args[1];
    if (args[0] == "resume" && args.size() >= 2)
        return args[0] + "_" + args[1];
    return args[0];
}

static bool executeCommand(const std::string &line, std::ostream &output) {
        std::vector<std::string> args = words(line);
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
                std::vector<std::string> responseWords = words(response);
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
            std::string response;
            if (!trackerRequest("download_file " + group + " " + hexEncode(name), response) ||
                response.rfind("META ", 0) != 0) {
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
                std::size_t lastColon = peerText.rfind(':');
                std::size_t firstColon = lastColon == std::string::npos ? std::string::npos :
                                         peerText.rfind(':', lastColon - 1);
                if (firstColon == std::string::npos || lastColon == std::string::npos) continue;
                Endpoint endpoint;
                if (parseEndpoint(peerText.substr(0, lastColon), endpoint)) {
                    std::string publicKey = peerText.substr(lastColon + 1);
                    std::string publicKeyBytes;
                    if (publicKey.size() >= 256 && hexDecode(publicKey, publicKeyBytes))
                        peers.push_back({endpoint, publicKey});
                }
            }
            if (peers.empty()) {
                output << "ERR no valid peer endpoints\n";
                return false;
            }
            auto status = std::make_shared<DownloadStatus>();
            status->group = group;
            status->name = name;
            status->total = metadata.pieceHashes.size();
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
        if (command == "list_files" && response.rfind("OK", 0) == 0) {
            for (std::size_t i = 1; i < words(response).size(); ++i) {
                std::string decoded;
                if (hexDecode(words(response)[i], decoded)) output << decoded << '\n';
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

static std::string safeCommandForLog(const std::string &line) {
    std::vector<std::string> args = words(line);
    if (args.empty()) return "";
    std::string command = canonicalCommand(args);
    if ((command == "login" || command == "create_user") && args.size() >= 2) {
        std::size_t userIndex = command == args[0] ? 1 : 2;
        if (userIndex < args.size()) return command + " " + args[userIndex] + " ********";
    }
    return line;
}

static std::string formatBytes(u64 bytes) {
    static const char *units[] = {"B", "KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream result;
    result << std::fixed << std::setprecision(unit == 0 ? 0 : 1) << value << ' ' << units[unit];
    return result.str();
}

struct DownloadView {
    std::shared_ptr<DownloadStatus> source;
    std::string group;
    std::string name;
    std::size_t completed = 0;
    std::size_t total = 0;
    bool finished = false;
    bool failed = false;
    u64 totalBytes = 0;
    u64 verifiedBytes = 0;
    u64 resumedBytes = 0;
    u64 elapsedMicros = 0;
    u64 activeRequests = 0;
    u64 retries = 0;
    u64 networkFailures = 0;
    u64 authenticationFailures = 0;
    u64 unavailableResponses = 0;
    std::size_t integrityFailures = 0;
    std::size_t discoveredPeers = 0;
    std::size_t responsivePeers = 0;
    std::size_t rarePieces = 0;
    std::size_t duplicateRequests = 0;
    DownloadTelemetry telemetry;
};

static std::vector<DownloadView> captureDownloadViews() {
    std::vector<std::shared_ptr<DownloadStatus>> statuses;
    {
        std::lock_guard<std::mutex> lock(downloadsMutex);
        statuses = downloads;
    }
    std::vector<DownloadView> result;
    result.reserve(statuses.size());
    for (const auto &status : statuses) {
        sampleDownloadSpeed(status);
        DownloadView view;
        view.source = status;
        view.group = status->group;
        view.name = status->name;
        view.completed = status->completed.load();
        view.total = status->total;
        view.finished = status->finished.load();
        view.failed = status->failed.load();
        view.totalBytes = status->totalBytes.load();
        view.verifiedBytes = status->verifiedBytes.load();
        view.resumedBytes = status->resumedVerifiedBytes.load();
        view.elapsedMicros = status->finalElapsedMicroseconds.load();
        if (!view.elapsedMicros)
            view.elapsedMicros = elapsedMicroseconds(status->started);
        view.activeRequests = status->activeRequests.load();
        view.retries = status->retries.load();
        view.networkFailures = status->networkFailures.load();
        view.authenticationFailures = status->authenticationFailures.load();
        view.unavailableResponses = status->unavailableResponses.load();
        view.integrityFailures = status->integrityFailures.load();
        view.discoveredPeers = status->discoveredPeers.load();
        view.responsivePeers = status->responsivePeers.load();
        view.rarePieces = status->rarePieces.load();
        view.duplicateRequests = status->duplicateRequests.load();
        {
            std::lock_guard<std::mutex> lock(status->telemetryMutex);
            view.telemetry = status->telemetry;
        }
        {
            std::lock_guard<std::mutex> lock(reputationMutex);
            for (auto &peer : view.telemetry.peers) {
                auto found = reputations.find(peer.endpoint);
                if (found == reputations.end()) continue;
                const PeerReputation &reputation = found->second;
                peer.trust = std::max(0.0, std::min(100.0,
                    100.0 - reputation.networkFailures * 2.0 -
                    reputation.authenticationFailures * 20.0 -
                    reputation.integrityFailures * 30.0));
                peer.throughputMiB = reputation.transferSeconds > 0.0
                    ? static_cast<double>(reputation.bytes) /
                      reputation.transferSeconds / (1024.0 * 1024.0) : 0.0;
                peer.failures = reputation.networkFailures +
                                reputation.authenticationFailures +
                                reputation.integrityFailures;
                peer.blacklisted = reputation.blacklistedUntil > std::time(nullptr);
            }
        }
        result.push_back(std::move(view));
    }
    return result;
}

static double viewSpeedMiB(const DownloadView &view) {
    double seconds = std::max(0.001, view.elapsedMicros / 1000000.0);
    u64 transferred = view.verifiedBytes > view.resumedBytes
        ? view.verifiedBytes - view.resumedBytes : 0;
    return static_cast<double>(transferred) / seconds / (1024.0 * 1024.0);
}

static std::string formatDuration(u64 microseconds) {
    if (microseconds < 1000000) {
        std::ostringstream shortDuration;
        shortDuration << std::fixed << std::setprecision(1)
                      << microseconds / 1000000.0 << "s";
        return shortDuration.str();
    }
    u64 seconds = microseconds / 1000000;
    std::ostringstream output;
    if (seconds >= 3600) output << seconds / 3600 << "h ";
    if (seconds >= 60) output << (seconds / 60) % 60 << "m ";
    output << seconds % 60 << "s";
    return output.str();
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
    using ftxui::Color;
    switch (state) {
        case PieceState::Unavailable: return Color::RGB(76, 87, 108);
        case PieceState::Available: return Color::RGB(67, 154, 180);
        case PieceState::Reserved: return Color::RGB(231, 178, 77);
        case PieceState::Downloading: return Color::RGB(244, 125, 66);
        case PieceState::Verified: return Color::RGB(75, 199, 144);
        case PieceState::Failed: return Color::RGB(235, 87, 87);
    }
    return Color::White;
}

static ftxui::Element pieceGrid(const DownloadView &view, int columns) {
    using namespace ftxui;
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
    if (rows.empty()) rows.push_back(text("No pieces (empty file)") | dim);
    return vbox(std::move(rows));
}

static ftxui::Element speedGraph(const DownloadView &view, std::size_t maxColumns) {
    using namespace ftxui;
    static const char *levels[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    if (view.telemetry.speedHistory.empty())
        return text("waiting for samples") | dim;
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
    return vbox({text(graph) | color(Color::RGB(67, 154, 180)),
                 text(label.str()) | dim});
}

static ftxui::Element completionModal(const DownloadView &view) {
    using namespace ftxui;
    const Color green = Color::RGB(75, 199, 144);
    const Color red = Color::RGB(235, 87, 87);
    double seconds = std::max(0.001, view.elapsedMicros / 1000000.0);
    double average = static_cast<double>(view.verifiedBytes) / seconds /
                     (1024.0 * 1024.0);
    std::ostringstream speed;
    speed << std::fixed << std::setprecision(2) << average << " MiB/s";
    Elements rows = {
        text(view.failed ? "TRANSFER FAILED" : "TRANSFER COMPLETE") |
            bold | color(view.failed ? red : green) | center,
        separator(),
        hbox({text("File          ") | dim, text(view.name)}),
        hbox({text("Size          ") | dim, text(formatBytes(view.totalBytes))}),
        hbox({text("Pieces        ") | dim,
              text(std::to_string(view.completed) + "/" + std::to_string(view.total))}),
        hbox({text("Duration      ") | dim, text(formatDuration(view.elapsedMicros))}),
        hbox({text("Average speed ") | dim, text(speed.str())}),
        hbox({text("Peers used    ") | dim,
              text(std::to_string(view.telemetry.peersUsed))}),
        hbox({text("Integrity     ") | dim,
              text(view.telemetry.integrityVerified ? "SHA1 verified" : "not verified") |
                  color(view.telemetry.integrityVerified ? green : red)}),
        hbox({text("Destination   ") | dim, text(view.telemetry.destination)}),
    };
    if (view.failed)
        rows.push_back(hbox({text("Reason        ") | dim,
                            text(view.telemetry.failureReason) | color(red)}));
    rows.push_back(separator());
    rows.push_back(text("Enter or Escape returns to the dashboard") | dim | center);
    return window(text(" Result "), vbox(std::move(rows))) |
           size(ftxui::WIDTH, ftxui::GREATER_THAN, 64) | clear_under | center;
}

static int runTui() {
    using namespace ftxui;
    const Color ink = Color::RGB(212, 222, 238);
    const Color muted = Color::RGB(119, 137, 166);
    const Color ocean = Color::RGB(67, 154, 180);
    const Color amber = Color::RGB(231, 178, 77);
    const Color green = Color::RGB(75, 199, 144);
    const Color red = Color::RGB(235, 87, 87);
    const Color base = Color::RGB(9, 16, 28);

    auto screen = ScreenInteractive::Fullscreen();
    std::string commandInput;
    std::deque<std::string> commandLog;
    commandLog.push_back("Ready. Press : to enter a command.");
    std::size_t selected = 0;
    std::optional<std::size_t> summary;
    bool commandMode = false;
    bool help = false;
    std::atomic<bool> refreshing{true};
    std::size_t observedDownloadCount = 0;

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
                text(" TORRENT ") | bold | bgcolor(ocean) | color(base),
                text("  secure swarm telemetry") | color(ink),
                filler(),
                text(aggregate.str()) | color(ocean) | bold,
                text("  ")
            }),
            hbox({
                text(" " + endpointKey(peerEndpoint)) | color(muted),
                text("  tracker " + std::to_string(trackerIndex + 1)) | color(muted),
                text(currentSession ? "  authenticated" : "  signed out") |
                    color(currentSession ? green : amber),
                filler(),
                text("↑↓ select   : command   F1 help   F10 exit ") | color(muted)
            }),
            separator() | color(ocean),
        });

        Elements transferRows;
        if (views.empty()) {
            transferRows.push_back(
                text("No downloads. Press : and run download file …") | color(muted));
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
                color(view.failed ? red : view.finished ? green : ink);
            if (index == selected) item = item | inverted | focus;
            transferRows.push_back(item);
        }
        Element transferList = window(text(" Swarm transfers "),
            vbox(std::move(transferRows)) | frame) |
            size(HEIGHT, LESS_THAN, 7);

        Element details;
        if (views.empty()) {
            details = vbox({
                filler(),
                text("The dashboard will populate when a download starts.") |
                    center | color(muted),
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
            Element torrentInfo = window(text(" Torrent information "), vbox({
                hbox({text(view.name) | bold, filler(),
                      text(view.telemetry.destination) | color(muted)}),
                gauge(static_cast<float>(progress)) |
                    color(view.failed ? red : green),
                text(progressText.str()) | color(ink),
            }));

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
            Element health = window(text(" Swarm health "),
                text(swarm.str()) | color(ink));

            Element legend = hbox({
                text("■ verified ") | color(stateColor(PieceState::Verified)),
                text("▼ active ") | color(stateColor(PieceState::Downloading)),
                text("◆ reserved ") | color(stateColor(PieceState::Reserved)),
                text("□ available ") | color(stateColor(PieceState::Available)),
                text("· unavailable ") | color(stateColor(PieceState::Unavailable)),
                text("! failed") | color(stateColor(PieceState::Failed)),
            });
            Element pieces = window(text(" Piece lifecycle "),
                vbox({pieceGrid(view, screen.dimx() >= 150 ? 48 : 32),
                      separator(), legend}));
            int dashboardWidth = std::max(40, screen.dimx());
            int leftWidth = dashboardWidth < 120 ? dashboardWidth :
                            std::max(60, dashboardWidth * 2 / 3);
            int rightWidth = std::max(40, dashboardWidth - leftWidth);
            std::size_t graphColumns = static_cast<std::size_t>(
                std::max(12, (leftWidth - 8) / 2));
            Element graph = window(
                text(" Rolling speed "), speedGraph(view, graphColumns));

            Elements peerRows = {
                hbox({text("endpoint") | bold | size(WIDTH, EQUAL, 24),
                      text("pieces") | bold | size(WIDTH, EQUAL, 9),
                      text("trust") | bold | size(WIDTH, EQUAL, 8),
                      text("MiB/s") | bold | size(WIDTH, EQUAL, 9),
                      text("state") | bold})
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
                        color(peer.blacklisted ? red : green),
                }));
            }
            if (view.telemetry.peers.empty())
                peerRows.push_back(text("Waiting for peer bitmaps") | color(muted));
            Element peersPanel = window(text(" Connected peers "),
                vbox(std::move(peerRows)) | frame);

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
                queueRows.push_back(text("Queue drained") | color(green));
            Element scheduler = window(text(" Rarest-first scheduler "),
                vbox(std::move(queueRows)));

            Elements workerRows = {
                hbox({text("worker") | bold | size(WIDTH, EQUAL, 7),
                      text("piece") | bold | size(WIDTH, EQUAL, 7),
                      text("peer") | bold | size(WIDTH, EQUAL, 20),
                      text("done") | bold | size(WIDTH, EQUAL, 6),
                      text("fail") | bold | size(WIDTH, EQUAL, 6),
                      text("MiB/s") | bold | size(WIDTH, EQUAL, 8),
                      text("state") | bold})
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
                              worker.state == "endgame" ? amber : muted),
                }));
            }
            if (view.telemetry.workers.empty())
                workerRows.push_back(text("No active workers") | color(muted));
            Element workersPanel = window(text(" Workers "),
                vbox(std::move(workerRows)));

            Elements eventRows;
            std::size_t first = view.telemetry.events.size() > 7
                ? view.telemetry.events.size() - 7 : 0;
            for (std::size_t i = first; i < view.telemetry.events.size(); ++i)
                eventRows.push_back(text("• " + view.telemetry.events[i]));
            if (eventRows.empty())
                eventRows.push_back(text("Waiting for protocol activity") | color(muted));
            Element events = window(text(" Protocol events "),
                vbox(std::move(eventRows)));

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
                                   color(error ? red : muted));
        }
        Element activity = window(text(" Command activity "),
            vbox(std::move(activityRows))) | size(HEIGHT, LESS_THAN, 5);
        Element commandBar = commandMode
            ? hbox({text(" : ") | bold | color(amber), text(commandInput),
                    text("█") | color(amber), filler(),
                    text("Enter run · Esc cancel ") | color(muted)})
            : hbox({text(" : command") | color(muted), filler(),
                    text("FTXUI live view ") | color(ocean)});

        Element dashboard = vbox({
            header,
            transferList,
            details | flex,
            activity,
            separator() | color(ocean),
            commandBar,
        }) | color(ink) | bgcolor(base);

        if (help) {
            Element helpModal = window(text(" Keyboard and commands "), vbox({
                text("↑ ↓ ← →   select a download"),
                text(":           open command bar"),
                text("Enter       execute command / close result"),
                text("Escape      close command bar, help, or result"),
                text("F1          toggle this help"),
                text("F10         exit"),
                separator(),
                text("The command bar accepts every classic CLI command.") | color(muted),
                text("Passwords are masked in command activity history.") | color(muted),
            })) | size(WIDTH, GREATER_THAN, 62) | clear_under | center;
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
        std::ostringstream output;
        bool quit = executeCommand(line, output);
        appendLog(commandLog, output.str());
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
            if (event == Event::Return) {
                if (commandInput.empty()) {
                    commandMode = false;
                    return true;
                }
                runCommand(commandInput);
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
            return true;
        }
        if (event == Event::ArrowUp || event == Event::ArrowLeft) {
            if (selected > 0) --selected;
            return true;
        }
        if (event == Event::ArrowDown || event == Event::ArrowRight) {
            std::lock_guard<std::mutex> lock(downloadsMutex);
            if (selected + 1 < downloads.size()) ++selected;
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
        !readTrackerInfo(argv[2])) {
        std::cerr << "usage: " << argv[0]
                  << " <peer-ip:port> tracker_info.txt [--tui]\n";
        return 1;
    }
    std::thread(peerServer).detach();
    return tui ? runTui() : runCli();
}

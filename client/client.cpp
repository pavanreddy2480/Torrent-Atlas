#include "../common/protocol.hpp"
#include "../common/sha1.hpp"
#include "../common/elgamal.hpp"

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>
#include <vector>

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
                                        std::string &responsePlain, double &seconds) {
    auto started = std::chrono::steady_clock::now();
    int fd = connectTcp(peer.endpoint.ip, peer.endpoint.port);
    if (fd < 0) return TransferResult::NetworkFailure;
    std::string clientPrivate, clientEphemeral, clientNonce = randomBytes(16);
    if (clientNonce.empty() ||
        !peerKey.generateEphemeral(clientPrivate, clientEphemeral)) {
        close(fd);
        return TransferResult::NetworkFailure;
    }
    std::string helloHeader = "20|" + std::to_string(std::time(nullptr)) + "|" +
                              hexEncode(clientNonce) + "|" + clientEphemeral + "|" +
                              peerKey.publicHex();
    ElGamalSignature clientProof = peerKey.sign(sha256(helloHeader));
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
    if (!peerKey.verify(sha256(transcript), {helloFields[4], helloFields[5]},
                        peer.publicKey)) {
        close(fd);
        return TransferResult::AuthenticationFailure;
    }
    std::string sharedSecret;
    if (!peerKey.deriveEphemeralSecret(clientPrivate, helloFields[2], sharedSecret)) {
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
    std::string cipher = aes256CbcEncrypt(encryptionKey, iv, plain);
    std::string requestHeader = "21|" + hexEncode(iv) + "|" + hexEncode(cipher);
    std::string request = requestHeader + "|" + hexEncode(hmacSha256(macKey, requestHeader));
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
    if (!constantTimeEqual(hmacSha256(macKey, responseHeader), responseTag))
        return TransferResult::AuthenticationFailure;
    if (!peerKey.verify(sha256(hexEncode(clientNonce)+"|"+fields[1]+"|"+sha256(responseCipher)),
                        {fields[2], fields[3]}, peer.publicKey))
        return TransferResult::AuthenticationFailure;
    if (!aes256CbcDecrypt(encryptionKey, responseIv, responseCipher, responsePlain))
        return TransferResult::AuthenticationFailure;
    return TransferResult::Success;
}

static TransferResult fetchPieceData(const PeerInfo &peer, const std::string &group,
                                     const std::string &name, const std::string &capability,
                                     std::size_t index, const std::string &expectedHash,
                                     std::string &piece) {
    double seconds = 0.0;
    TransferResult result = securePeerRequest(
        peer, "GET\n" + group + "\n" + name + "\n" + std::to_string(index) + "\n" + capability,
        piece, seconds);
    if (result != TransferResult::Success) {
        recordPeerResult(peer, result);
        return result;
    }
    const char *data = piece.data();
    std::size_t length = piece.size();
    Sha1 pieceHash;
    pieceHash.update(data, length);
    if (pieceHash.finalHex() != expectedHash) {
        recordPeerResult(peer, TransferResult::IntegrityFailure);
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
                                 int outputFd) {
    std::string piece;
    TransferResult result = fetchPieceData(
        peer, group, name, capability, index, expectedHash, piece);
    if (result == TransferResult::Success && !writePiece(outputFd, index, piece))
        return TransferResult::NetworkFailure;
    return result;
}

static bool fetchBitmap(const PeerInfo &peer, const std::string &group,
                        const std::string &name, const std::string &capability,
                        std::size_t pieceCount, std::vector<unsigned char> &bitmap) {
    std::string response;
    double seconds = 0.0;
    TransferResult result = securePeerRequest(
        peer, "BITMAP\n" + group + "\n" + name + "\n0\n" + capability, response, seconds);
    if (result != TransferResult::Success || response.size() != pieceCount) {
        recordPeerResult(peer, result == TransferResult::Success
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
        status->failed = true;
        status->finished = true;
        return;
    }

    const std::size_t pieceCount = metadata.pieceHashes.size();
    if (!resuming) resumedPieces.assign(pieceCount, 0);
    verifyStoredPieces(output, metadata, resumedPieces);
    status->completed = static_cast<std::size_t>(
        std::count(resumedPieces.begin(), resumedPieces.end(), static_cast<unsigned char>(1)));
    status->resumedPieces = status->completed.load();
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
            status->failed = true;
            status->finished = true;
            return;
        }
    }

    std::vector<std::vector<unsigned char>> peerBitmaps(peers.size());
    for (std::size_t peer = 0; peer < peers.size(); ++peer)
        fetchBitmap(peers[peer], group, name, metadata.capability, pieceCount, peerBitmaps[peer]);

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
        fsync(output);
        {
            std::lock_guard<std::mutex> lock(resume->mutex);
            if (piece < resume->verified.size()) resume->verified[piece] = 1;
            saveResumeLocked(*resume);
        }
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
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < workerCount; ++worker) {
        workers.emplace_back([&] {
            for (;;) {
                std::size_t position = nextOrder.fetch_add(1);
                if (position >= normalCount) break;
                std::size_t piece = order[position];
                bool obtained = false;
                for (int round = 0; round < 2 && !obtained; ++round) {
                    std::vector<std::size_t> candidates = candidatesFor(piece);
                    for (std::size_t peer : candidates) {
                        TransferResult result = fetchPiece(
                            peers[peer], group, name, metadata.capability, piece,
                            metadata.pieceHashes[piece], output);
                        if (result == TransferResult::IntegrityFailure)
                            ++status->integrityFailures;
                        if (result == TransferResult::Success) {
                            obtained = true;
                            markAvailable(piece);
                            ++status->completed;
                            break;
                        }
                    }
                    if (!obtained) std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                if (!obtained) failure = true;
            }
        });
    }
    for (auto &worker : workers) worker.join();

    // Endgame mode duplicates the final few requests across the two best peers. The first
    // verified response wins, reducing tail latency from one slow or disconnected seeder.
    for (std::size_t position = normalCount; position < missingCount; ++position) {
        std::size_t piece = order[position];
        std::vector<std::size_t> candidates = candidatesFor(piece);
        if (candidates.empty()) {
            failure = true;
            continue;
        }
        std::size_t requestCount = std::min<std::size_t>(2, candidates.size());
        if (requestCount > 1) status->duplicateRequests += requestCount - 1;
        struct EndgameState {
            std::mutex mutex;
            std::condition_variable condition;
            std::size_t completed = 0;
            bool won = false;
            std::string piece;
        };
        auto endgame = std::make_shared<EndgameState>();
        for (std::size_t request = 0; request < requestCount; ++request) {
            PeerInfo peer = peers[candidates[request]];
            std::string groupCopy = group, nameCopy = name;
            std::string capabilityCopy = metadata.capability;
            std::string expectedHash = metadata.pieceHashes[piece];
            auto statusCopy = status;
            std::thread([endgame, peer, groupCopy, nameCopy, capabilityCopy, expectedHash,
                         statusCopy, piece] {
                std::string data;
                TransferResult result = fetchPieceData(
                    peer, groupCopy, nameCopy, capabilityCopy, piece, expectedHash, data);
                if (result == TransferResult::IntegrityFailure)
                    ++statusCopy->integrityFailures;
                {
                    std::lock_guard<std::mutex> lock(endgame->mutex);
                    ++endgame->completed;
                    if (result == TransferResult::Success && !endgame->won) {
                        endgame->won = true;
                        endgame->piece = std::move(data);
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
            if (endgame->won && writePiece(output, piece, endgame->piece)) {
                markAvailable(piece);
                ++status->completed;
            } else {
                failure = true;
            }
        }
    }
    close(output);

    u64 verifiedSize = 0;
    std::string verifiedHash;
    std::vector<std::string> verifiedPieces;
    if (failure || !hashFile(temporary, verifiedSize, verifiedHash, verifiedPieces) ||
        verifiedSize != metadata.size || verifiedHash != metadata.fullHash ||
        rename(temporary.c_str(), destination.c_str()) != 0) {
        status->failed = true;
    } else {
        unlink(manifestPath.c_str());
        metadata.path = destination;
        metadata.available.assign(pieceCount, 1);
        std::string registrationResponse;
        trackerRequest(uploadCommand(group, name, metadata), registrationResponse);
        std::lock_guard<std::mutex> lock(sharedMutex);
        sharedFiles[keyFor(group, name)] = metadata;
    }
    status->finished = true;
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

int main(int argc, char **argv) {
    if (argc != 3 || !parseEndpoint(argv[1], peerEndpoint) || !readTrackerInfo(argv[2])) {
        std::cerr << "usage: " << argv[0] << " <peer-ip:port> tracker_info.txt\n";
        return 1;
    }
    std::thread(peerServer).detach();
    std::cout << "Client listening on " << peerEndpoint.ip << ':' << peerEndpoint.port << '\n';

    std::string line;
    while (std::cout << "> " && std::getline(std::cin, line)) {
        std::vector<std::string> args = words(line);
        if (args.empty()) continue;
        if (args[0] == "quit") break;
        std::string command = canonicalCommand(args);
        std::size_t offset = command == args[0] ? 1 : 2;

        if (command == "upload_file") {
            if (args.size() < offset + 2) {
                std::cout << "ERR usage: upload_file <group> <path>\n";
                continue;
            }
            std::string group = args[offset], path = args[offset + 1], name = baseName(path);
            LocalFile file;
            file.path = path;
            file.capability = hexEncode(randomBytes(32));
            if (file.capability.size() != 64) {
                std::cout << "ERR secure random generation failed\n";
                continue;
            }
            if (!hashFile(path, file.size, file.fullHash, file.pieceHashes)) {
                perror("upload file");
                continue;
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
                std::cout << "OK file shared\n";
            } else {
                std::cout << response << '\n';
            }
            continue;
        }
        if (command == "download_file" || command == "resume_download") {
            if (args.size() < offset + 3) {
                std::cout << "ERR usage: " << command
                          << " <group> <file-name> <destination>\n";
                continue;
            }
            std::string group = args[offset], name = args[offset + 1], destination = args[offset + 2];
            std::string response;
            if (!trackerRequest("download_file " + group + " " + hexEncode(name), response) ||
                response.rfind("META ", 0) != 0) {
                std::cout << response << '\n';
                continue;
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
                std::cout << "ERR no valid peer endpoints\n";
                continue;
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
            std::cout << "OK download started\n";
            continue;
        }
        if (command == "show_downloads") {
            std::lock_guard<std::mutex> lock(downloadsMutex);
            for (const auto &status : downloads) {
                char state = status->finished ? (status->failed ? 'F' : 'C') : 'D';
                std::cout << '[' << state << "] [" << status->group << "] " << status->name;
                if (!status->finished)
                    std::cout << " (" << status->completed << '/' << status->total << " pieces)";
                std::cout << " rare=" << status->rarePieces
                          << " resumed=" << status->resumedPieces
                          << " endgame-duplicates=" << status->duplicateRequests
                          << " integrity-failures=" << status->integrityFailures;
                std::cout << '\n';
            }
            continue;
        }
        if (command == "peer_stats" || command == "show_peers") {
            std::lock_guard<std::mutex> lock(reputationMutex);
            if (reputations.empty()) {
                std::cout << "No peer observations yet\n";
                continue;
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
                std::cout << entry.first << " trust=" << std::fixed << std::setprecision(1)
                          << trust << " speed=" << throughput << "MiB/s"
                          << " ok=" << reputation.successes
                          << " network=" << reputation.networkFailures
                          << " auth=" << reputation.authenticationFailures
                          << " corrupt=" << reputation.integrityFailures
                          << " status=" << (blacklisted ? "BLACKLISTED" : "ACTIVE") << '\n';
            }
            continue;
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
                if (hexDecode(words(response)[i], decoded)) std::cout << decoded << '\n';
            }
        } else {
            std::cout << response << '\n';
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
    }
    return 0;
}

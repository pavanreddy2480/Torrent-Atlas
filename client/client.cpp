#include "../common/protocol.hpp"
#include "../common/sha1.hpp"
#include "../common/elgamal.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
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
static std::atomic<u64> temporarySequence{1};
static ElGamalKey peerKey;
static std::mutex replayMutex;
static std::unordered_map<std::string, std::time_t> seenNonces;

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
    std::string request;
    if (!receiveFrame(fd, request)) {
        close(fd);
        return;
    }
    std::vector<std::string> fields = split(request, '|');
    if (fields.size() != 8 || fields[0] != "20") {
        sendFrame(fd, "60|malformed");
        close(fd);
        return;
    }
    std::time_t timestamp = 0;
    try { timestamp = static_cast<std::time_t>(std::stoll(fields[1])); }
    catch (...) { sendFrame(fd, "60|timestamp"); close(fd); return; }
    std::time_t now = std::time(nullptr);
    if (timestamp < now - 60 || timestamp > now + 60) {
        sendFrame(fd, "60|stale");
        close(fd);
        return;
    }
    std::string clientNonce, requestIv, requestCipher, requestTag;
    if (!hexDecode(fields[2], clientNonce) || clientNonce.size() != 16 ||
        !hexDecode(fields[5], requestIv) || requestIv.size() != 16 ||
        !hexDecode(fields[6], requestCipher) || !hexDecode(fields[7], requestTag)) {
        sendFrame(fd, "60|encoding"); close(fd); return;
    }
    {
        std::lock_guard<std::mutex> lock(replayMutex);
        for (auto it = seenNonces.begin(); it != seenNonces.end();) {
            if (it->second < now - 120) it = seenNonces.erase(it); else ++it;
        }
        if (seenNonces.count(fields[2])) {
            sendFrame(fd, "60|replay"); close(fd); return;
        }
    }
    std::string sessionKey;
    if (!peerKey.decrypt({fields[3], fields[4]}, sessionKey, 32)) {
        sendFrame(fd, "60|key"); close(fd); return;
    }
    std::string encryptionKey = sha256(sessionKey + "ENC");
    std::string macKey = sha256(sessionKey + "MAC");
    std::string authenticated = fields[0]+"|"+fields[1]+"|"+fields[2]+"|"+fields[3]+"|"+
                                fields[4]+"|"+fields[5]+"|"+fields[6];
    if (!constantTimeEqual(hmacSha256(macKey, authenticated), requestTag)) {
        sendFrame(fd, "60|hmac"); close(fd); return;
    }
    std::string requestPlain;
    if (!aes256CbcDecrypt(encryptionKey, requestIv, requestCipher, requestPlain)) {
        sendFrame(fd, "60|decrypt"); close(fd); return;
    }
    std::vector<std::string> requestParts = split(requestPlain, '\n');
    if (requestParts.size() != 4) { sendFrame(fd, "60|request"); close(fd); return; }
    std::string group = requestParts[0], name = requestParts[1], capability = requestParts[3];
    std::size_t pieceIndex = 0;
    try { pieceIndex = static_cast<std::size_t>(std::stoull(requestParts[2])); }
    catch (...) { sendFrame(fd, "60|piece"); close(fd); return; }
    {
        std::lock_guard<std::mutex> lock(replayMutex);
        if (!seenNonces.emplace(fields[2], timestamp).second) {
            sendFrame(fd, "60|replay"); close(fd); return;
        }
    }
    LocalFile file;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(sharedMutex);
        auto it = sharedFiles.find(keyFor(group, name));
        if (it != sharedFiles.end() && pieceIndex < it->second.pieceHashes.size() &&
            constantTimeEqual(it->second.capability, capability)) {
            file = it->second;
            found = true;
        }
    }
    if (!found) {
        sendFrame(fd, "60|unauthorized");
        close(fd);
        return;
    }

    std::size_t expected = static_cast<std::size_t>(
        std::min<u64>(PIECE_SIZE, file.size - static_cast<u64>(pieceIndex) * PIECE_SIZE));
    std::string piece(expected, '\0');
    int fileFd = open(file.path.c_str(), O_RDONLY);
    if (fileFd < 0) {
        sendFrame(fd, std::string(1, '\1') + "file open failed");
        close(fd);
        return;
    }
    std::size_t received = 0;
    off_t offset = static_cast<off_t>(pieceIndex * PIECE_SIZE);
    while (received < expected) {
        ssize_t count = pread(fileFd, &piece[received], expected - received,
                              offset + static_cast<off_t>(received));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        received += static_cast<std::size_t>(count);
    }
    close(fileFd);
    if (received != expected) {
        sendFrame(fd, "60|read");
    } else {
        std::string serverNonce = randomBytes(16), responseIv = randomBytes(16);
        std::string responseCipher = aes256CbcEncrypt(encryptionKey, responseIv, piece);
        ElGamalSignature signature = peerKey.sign(
            sha256(fields[2] + "|" + hexEncode(serverNonce) + "|" + sha256(responseCipher)));
        std::string responseHeader = "30|" + hexEncode(serverNonce) + "|" + signature.r + "|" +
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

static bool fetchPiece(const PeerInfo &peer, const std::string &group, const std::string &name,
                       const std::string &capability, std::size_t index,
                       const std::string &expectedHash, int outputFd) {
    int fd = connectTcp(peer.endpoint.ip, peer.endpoint.port);
    if (fd < 0) return false;
    std::string sessionKey = randomBytes(32), clientNonce = randomBytes(16), iv = randomBytes(16);
    if (sessionKey.empty() || clientNonce.empty() || iv.empty()) { close(fd); return false; }
    ElGamalCipher encryptedKey = peerKey.encrypt(sessionKey, peer.publicKey);
    if (encryptedKey.c1.empty() || encryptedKey.c2.empty()) { close(fd); return false; }
    std::string encryptionKey = sha256(sessionKey + "ENC");
    std::string macKey = sha256(sessionKey + "MAC");
    std::string plain = group + "\n" + name + "\n" + std::to_string(index) + "\n" + capability;
    std::string cipher = aes256CbcEncrypt(encryptionKey, iv, plain);
    std::string requestHeader = "20|" + std::to_string(std::time(nullptr)) + "|" +
                                hexEncode(clientNonce) + "|" + encryptedKey.c1 + "|" +
                                encryptedKey.c2 + "|" + hexEncode(iv) + "|" + hexEncode(cipher);
    std::string request = requestHeader + "|" + hexEncode(hmacSha256(macKey, requestHeader));
    std::string response;
    bool ok = sendFrame(fd, request) && receiveFrame(fd, response);
    close(fd);
    std::vector<std::string> fields = split(response, '|');
    if (!ok || fields.size() != 7 || fields[0] != "30") return false;
    std::string serverNonce, responseIv, responseCipher, responseTag;
    if (!hexDecode(fields[1], serverNonce) || serverNonce.size()!=16 ||
        !hexDecode(fields[4], responseIv) || responseIv.size()!=16 ||
        !hexDecode(fields[5], responseCipher) || !hexDecode(fields[6], responseTag)) return false;
    std::string responseHeader = fields[0]+"|"+fields[1]+"|"+fields[2]+"|"+fields[3]+"|"+fields[4]+"|"+fields[5];
    if (!constantTimeEqual(hmacSha256(macKey, responseHeader), responseTag)) return false;
    if (!peerKey.verify(sha256(hexEncode(clientNonce)+"|"+fields[1]+"|"+sha256(responseCipher)),
                        {fields[2], fields[3]}, peer.publicKey)) return false;
    std::string piece;
    if (!aes256CbcDecrypt(encryptionKey, responseIv, responseCipher, piece)) return false;
    const char *data = piece.data();
    std::size_t length = piece.size();
    Sha1 pieceHash;
    pieceHash.update(data, length);
    if (pieceHash.finalHex() != expectedHash) return false;

    std::size_t written = 0;
    off_t offset = static_cast<off_t>(index * PIECE_SIZE);
    while (written < length) {
        ssize_t count = pwrite(outputFd, data + written, length - written,
                               offset + static_cast<off_t>(written));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return true;
}

static void downloadFile(std::string group, std::string name, std::string destination,
                         LocalFile metadata, std::vector<PeerInfo> peers,
                         std::shared_ptr<DownloadStatus> status) {
    struct stat info{};
    if (stat(destination.c_str(), &info) == 0 && S_ISDIR(info.st_mode))
        destination += (destination.back() == '/' ? "" : "/") + name;
    std::string temporary = destination + ".part." + std::to_string(getpid()) + "." +
                            std::to_string(temporarySequence.fetch_add(1));
    int output = open(temporary.c_str(), O_CREAT | O_EXCL | O_RDWR, 0644);
    if (output < 0 || ftruncate(output, static_cast<off_t>(metadata.size)) < 0) {
        if (output >= 0) close(output);
        unlink(temporary.c_str());
        status->failed = true;
        status->finished = true;
        return;
    }

    std::atomic<std::size_t> nextPiece{0};
    std::atomic<bool> failure{false};
    std::size_t workerCount = std::min<std::size_t>(
        8, std::max<std::size_t>(1, std::min(peers.size(), metadata.pieceHashes.size())));
    std::vector<std::thread> workers;
    for (std::size_t worker = 0; worker < workerCount; ++worker) {
        workers.emplace_back([&, worker] {
            for (;;) {
                std::size_t piece = nextPiece.fetch_add(1);
                if (piece >= metadata.pieceHashes.size()) break;
                bool obtained = false;
                for (int round = 0; round < 3 && !obtained; ++round) {
                    for (std::size_t attempt = 0; attempt < peers.size(); ++attempt) {
                        const PeerInfo &peer = peers[(piece + worker + attempt) % peers.size()];
                        if (fetchPiece(peer, group, name, metadata.capability, piece,
                                       metadata.pieceHashes[piece], output)) {
                            obtained = true;
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
    close(output);

    u64 verifiedSize = 0;
    std::string verifiedHash;
    std::vector<std::string> verifiedPieces;
    if (failure || !hashFile(temporary, verifiedSize, verifiedHash, verifiedPieces) ||
        verifiedSize != metadata.size || verifiedHash != metadata.fullHash ||
        rename(temporary.c_str(), destination.c_str()) != 0) {
        unlink(temporary.c_str());
        status->failed = true;
    } else {
        metadata.path = destination;
        std::string registrationResponse;
        trackerRequest(uploadCommand(group, name, metadata), registrationResponse);
        if (registrationResponse.rfind("OK", 0) == 0) {
            std::lock_guard<std::mutex> lock(sharedMutex);
            sharedFiles[keyFor(group, name)] = metadata;
        }
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
        if (command == "download_file") {
            if (args.size() < offset + 3) {
                std::cout << "ERR usage: download_file <group> <file-name> <destination>\n";
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
                std::cout << '\n';
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

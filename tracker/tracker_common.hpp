#pragma once

#include "../common/protocol.hpp"
#include "../common/secure_crypto.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct Endpoint {
    std::string ip;
    int port = 0;
};

struct SeederInfo {
    Endpoint endpoint;
    std::string publicKey;
};

struct FileInfo {
    u64 size = 0;
    std::string fullHash;
    std::string capability;
    std::vector<std::string> pieceHashes;
    std::unordered_map<std::string, SeederInfo> seeders;
};

struct GroupInfo {
    std::string owner;
    std::unordered_set<std::string> members;
    std::unordered_set<std::string> pending;
    std::unordered_map<std::string, FileInfo> files;
};

struct HandleResult {
    std::string response;
    u64 session = 0;
    bool shouldSync = false;
};

class TrackerState {
    struct LoginThrottle {
        unsigned failures = 0;
        std::chrono::steady_clock::time_point lockedUntil{};
    };

    std::mutex mutex_;
    std::unordered_map<std::string, std::string> users_;
    std::unordered_map<u64, std::string> sessions_;
    std::unordered_map<std::string, GroupInfo> groups_;
    std::unordered_map<std::string, LoginThrottle> loginThrottles_;
    std::atomic<u64> sequence_{1};
    u64 trackerTag_;
    static constexpr std::uint32_t PASSWORD_ITERATIONS = 20000;

    static std::string encodePassword(const std::string &password) {
        std::string salt = randomBytes(16);
        if (salt.size() != 16) return {};
        std::string digest = pbkdf2HmacSha256(
            password, salt, PASSWORD_ITERATIONS, 32);
        return "pbkdf2-sha256$" + std::to_string(PASSWORD_ITERATIONS) + "$" +
               hexEncode(salt) + "$" + hexEncode(digest);
    }

    static bool verifyPassword(const std::string &password,
                               const std::string &encoded) {
        std::vector<std::string> fields = split(encoded, '$');
        if (fields.size() != 4 || fields[0] != "pbkdf2-sha256") return false;
        std::uint32_t iterations = 0;
        try {
            iterations = static_cast<std::uint32_t>(std::stoul(fields[1]));
        } catch (...) {
            return false;
        }
        if (iterations == 0 || iterations > 1000000) return false;
        std::string salt, expected;
        if (!hexDecode(fields[2], salt) || !hexDecode(fields[3], expected) ||
            salt.size() != 16 || expected.size() != 32)
            return false;
        std::string actual = pbkdf2HmacSha256(
            password, salt, iterations, expected.size());
        bool valid = constantTimeEqual(actual, expected);
        secureErase(actual);
        return valid;
    }

    u64 createSessionId() {
        for (int attempt = 0; attempt < 16; ++attempt) {
            std::string bytes = randomBytes(sizeof(u64));
            if (bytes.size() != sizeof(u64)) return 0;
            u64 random = 0;
            std::memcpy(&random, bytes.data(), sizeof(random));
            u64 session = trackerTag_ | (random & 0x00ffffffffffffffULL);
            if (session != 0 && !sessions_.count(session)) return session;
        }
        return 0;
    }

    static std::string joinHashes(const std::vector<std::string> &hashes) {
        std::string result;
        for (std::size_t i = 0; i < hashes.size(); ++i) {
            if (i) result.push_back(',');
            result += hashes[i];
        }
        return result;
    }

    void removeUserShares(const std::string &user) {
        for (auto &groupEntry : groups_) {
            for (auto file = groupEntry.second.files.begin(); file != groupEntry.second.files.end();) {
                file->second.seeders.erase(user);
                if (file->second.seeders.empty()) file = groupEntry.second.files.erase(file);
                else ++file;
            }
        }
    }

public:
    explicit TrackerState(unsigned trackerNumber)
        : trackerTag_(static_cast<u64>(trackerNumber & 0xffU) << 56U) {}

    bool empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return users_.empty() && groups_.empty();
    }

    std::string serialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream output;
        for (const auto &entry : users_)
            output << "U " << hexEncode(entry.first) << ' ' << hexEncode(entry.second) << '\n';
        for (const auto &entry : sessions_)
            output << "S " << entry.first << ' ' << hexEncode(entry.second) << '\n';
        for (const auto &groupEntry : groups_) {
            const GroupInfo &group = groupEntry.second;
            std::string encodedGroup = hexEncode(groupEntry.first);
            output << "G " << encodedGroup << ' ' << hexEncode(group.owner) << '\n';
            for (const auto &member : group.members)
                output << "M " << encodedGroup << ' ' << hexEncode(member) << '\n';
            for (const auto &pending : group.pending)
                output << "R " << encodedGroup << ' ' << hexEncode(pending) << '\n';
            for (const auto &fileEntry : group.files) {
                const FileInfo &file = fileEntry.second;
                std::string encodedFile = hexEncode(fileEntry.first);
                output << "F " << encodedGroup << ' ' << encodedFile << ' ' << file.size << ' '
                       << file.fullHash << ' ' << file.capability << ' '
                       << (file.pieceHashes.empty() ? "-" : joinHashes(file.pieceHashes)) << '\n';
                for (const auto &seeder : file.seeders)
                    output << "D " << encodedGroup << ' ' << encodedFile << ' '
                           << hexEncode(seeder.first) << ' ' << hexEncode(seeder.second.endpoint.ip) << ' '
                           << seeder.second.endpoint.port << ' ' << seeder.second.publicKey << '\n';
            }
        }
        return output.str();
    }

    bool replaceFromSnapshot(const std::string &snapshot) {
        std::unordered_map<std::string, std::string> users;
        std::unordered_map<u64, std::string> sessions;
        std::unordered_map<std::string, GroupInfo> groups;
        std::istringstream input(snapshot);
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            std::istringstream record(line);
            char type = '\0';
            record >> type;
            std::string a, b, c, d;
            if (type == 'U') {
                record >> a >> b;
                std::string user, password;
                if (!hexDecode(a, user) || !hexDecode(b, password)) return false;
                users[user] = password;
            } else if (type == 'S') {
                u64 session = 0;
                record >> session >> a;
                std::string user;
                if (!record || !hexDecode(a, user)) return false;
                sessions[session] = user;
            } else if (type == 'G') {
                record >> a >> b;
                std::string group, owner;
                if (!hexDecode(a, group) || !hexDecode(b, owner)) return false;
                groups[group].owner = owner;
            } else if (type == 'M' || type == 'R') {
                record >> a >> b;
                std::string group, user;
                if (!hexDecode(a, group) || !hexDecode(b, user)) return false;
                if (type == 'M') groups[group].members.insert(user);
                else groups[group].pending.insert(user);
            } else if (type == 'F') {
                u64 size = 0;
                std::string capability;
                record >> a >> b >> size >> c >> capability >> d;
                std::string group, name;
                if (!record || !hexDecode(a, group) || !hexDecode(b, name)) return false;
                FileInfo &file = groups[group].files[name];
                file.size = size;
                file.fullHash = c;
                file.capability = capability;
                file.pieceHashes = d == "-" ? std::vector<std::string>{} : split(d, ',');
            } else if (type == 'D') {
                int port = 0;
                std::string publicKey;
                record >> a >> b >> c >> d >> port >> publicKey;
                std::string group, name, user, ip;
                if (!record || !hexDecode(a, group) || !hexDecode(b, name) ||
                    !hexDecode(c, user) || !hexDecode(d, ip)) return false;
                groups[group].files[name].seeders[user] = {{ip, port}, publicKey};
            } else {
                return false;
            }
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            users_ = std::move(users);
            sessions_ = std::move(sessions);
            groups_ = std::move(groups);
        }
        return true;
    }

    HandleResult handle(u64 session, const std::string &commandLine, bool replicated) {
        std::istringstream input(commandLine);
        std::string command;
        input >> command;
        if (command.empty()) return {"ERR empty command", session, false};

        std::lock_guard<std::mutex> lock(mutex_);
        std::string user;
        auto sessionIt = sessions_.find(session);
        if (sessionIt != sessions_.end()) user = sessionIt->second;
        auto requireLogin = [&]() -> bool { return !user.empty(); };

        if (command == "create_user") {
            std::string name, password;
            input >> name >> password;
            if (name.empty() || password.empty()) return {"ERR usage: create_user <user> <password>", session, false};
            if (users_.count(name)) {
                if (replicated && verifyPassword(password, users_[name]))
                    return {"OK already replicated", session, false};
                return {"ERR user already exists", session, false};
            }
            std::string encoded = encodePassword(password);
            secureErase(password);
            if (encoded.empty())
                return {"ERR secure random generation failed", session, false};
            users_[name] = std::move(encoded);
            return {"OK user created", session, true};
        }
        if (command == "login") {
            std::string name, password;
            input >> name >> password;
            if (requireLogin()) {
                if (replicated && user == name) return {"OK already logged in", session, false};
                return {"ERR logout before logging in again", session, false};
            }
            if (!users_.count(name)) return {"ERR no such user", session, false};
            LoginThrottle &throttle = loginThrottles_[name];
            auto now = std::chrono::steady_clock::now();
            if (throttle.lockedUntil > now) {
                secureErase(password);
                return {"ERR too many login attempts; try again later", session, false};
            }
            bool passwordValid = verifyPassword(password, users_[name]);
            secureErase(password);
            if (!passwordValid) {
                if (++throttle.failures >= 5) {
                    throttle.failures = 0;
                    throttle.lockedUntil = now + std::chrono::seconds(30);
                    return {"ERR too many login attempts; try again later", session, false};
                }
                return {"ERR invalid password", session, false};
            }
            loginThrottles_.erase(name);
            if (session == 0) {
                session = createSessionId();
                if (session == 0)
                    return {"ERR secure random generation failed", 0, false};
            }
            sessions_[session] = name;
            return {"OK logged in", session, true};
        }
        if (command == "logout") {
            if (!requireLogin())
                return replicated ? HandleResult{"OK already logged out", session, false}
                                  : HandleResult{"ERR not logged in", session, false};
            removeUserShares(user);
            sessions_.erase(session);
            return {"OK logged out", 0, true};
        }
        if (command == "create_group") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty()) return {"ERR usage: create_group <group>", session, false};
            if (groups_.count(group)) {
                if (replicated && groups_[group].owner == user)
                    return {"OK already replicated", session, false};
                return {"ERR group already exists", session, false};
            }
            GroupInfo info;
            info.owner = user;
            info.members.insert(user);
            groups_[group] = std::move(info);
            return {"OK group created", session, true};
        }
        if (command == "join_group") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (it->second.members.count(user))
                return replicated ? HandleResult{"OK already a member", session, false}
                                  : HandleResult{"ERR already a member", session, false};
            if (!it->second.pending.insert(user).second)
                return replicated ? HandleResult{"OK already replicated", session, false}
                                  : HandleResult{"ERR request already pending", session, false};
            return {"OK join requested", session, true};
        }
        if (command == "leave_group") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (it->second.owner == user) return {"ERR owner cannot leave group", session, false};
            if (!it->second.members.erase(user))
                return replicated ? HandleResult{"OK already absent", session, false}
                                  : HandleResult{"ERR not a member", session, false};
            for (auto file = it->second.files.begin(); file != it->second.files.end();) {
                file->second.seeders.erase(user);
                if (file->second.seeders.empty()) file = it->second.files.erase(file);
                else ++file;
            }
            return {"OK left group", session, true};
        }
        if (command == "list_groups") {
            if (!requireLogin()) return {"ERR login required", session, false};
            std::string response = "OK";
            for (const auto &entry : groups_) response += " " + entry.first;
            return {response, session, false};
        }
        if (command == "list_requests") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (it->second.owner != user) return {"ERR only owner may list requests", session, false};
            std::string response = "OK";
            for (const auto &name : it->second.pending) response += " " + name;
            return {response, session, false};
        }
        if (command == "accept_request") {
            std::string group, name;
            input >> group >> name;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (it->second.owner != user) return {"ERR only owner may accept requests", session, false};
            if (!it->second.pending.erase(name)) {
                if (replicated && it->second.members.count(name)) return {"OK already replicated", session, false};
                return {"ERR no such pending request", session, false};
            }
            it->second.members.insert(name);
            return {"OK request accepted", session, true};
        }
        if (command == "upload_file") {
            std::string group, encodedName, fullHash, capability, hashes, ip, publicKey;
            u64 size = 0;
            int port = 0;
            input >> group >> encodedName >> size >> fullHash >> capability >> hashes >> ip >> port >> publicKey;
            std::string name;
            std::string capabilityBytes;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto groupIt = groups_.find(group);
            if (groupIt == groups_.end()) return {"ERR no such group", session, false};
            if (!groupIt->second.members.count(user)) return {"ERR not a group member", session, false};
            std::string publicKeyBytes;
            if (!hexDecode(encodedName, name) || !hexDecode(capability, capabilityBytes) ||
                !hexDecode(publicKey, publicKeyBytes) ||
                publicKeyBytes.size() != 32 || name.empty() || fullHash.size() != 40 ||
                capability.size() != 64 || ip.empty() || port <= 0 ||
                capabilityBytes.size() != 32)
                return {"ERR invalid upload metadata", session, false};
            std::vector<std::string> pieceHashes = hashes == "-" ? std::vector<std::string>{} : split(hashes, ',');
            std::size_t expectedPieces = static_cast<std::size_t>((size + PIECE_SIZE - 1) / PIECE_SIZE);
            if (pieceHashes.size() != expectedPieces) return {"ERR invalid piece hash count", session, false};
            for (const auto &hash : pieceHashes) if (hash.size() != 40) return {"ERR invalid piece hash", session, false};

            FileInfo &file = groupIt->second.files[name];
            if (!file.fullHash.empty() &&
                (file.size != size || file.fullHash != fullHash || file.pieceHashes != pieceHashes))
                return {"ERR conflicting file metadata", session, false};
            if (file.fullHash.empty()) {
                file.size = size;
                file.fullHash = fullHash;
                file.capability = capability;
                file.pieceHashes = std::move(pieceHashes);
            }
            file.seeders[user] = {{ip, port}, publicKey};
            return {"OK file shared " + file.capability, session, true};
        }
        if (command == "list_files") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (!it->second.members.count(user)) return {"ERR not a group member", session, false};
            std::string response = "OK";
            for (const auto &entry : it->second.files) response += " " + hexEncode(entry.first);
            return {response, session, false};
        }
        if (command == "download_file") {
            std::string group, encodedName, name;
            input >> group >> encodedName;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto groupIt = groups_.find(group);
            if (groupIt == groups_.end()) return {"ERR no such group", session, false};
            if (!groupIt->second.members.count(user)) return {"ERR not a group member", session, false};
            if (!hexDecode(encodedName, name)) return {"ERR invalid file name", session, false};
            auto fileIt = groupIt->second.files.find(name);
            if (fileIt == groupIt->second.files.end() || fileIt->second.seeders.empty())
                return {"ERR file has no online seeders", session, false};
            const FileInfo &file = fileIt->second;
            std::string response = "META " + std::to_string(file.size) + " " + file.fullHash + " " +
                                   file.capability + " " +
                                   (file.pieceHashes.empty() ? "-" : joinHashes(file.pieceHashes)) + " ";
            bool first = true;
            for (const auto &seeder : file.seeders) {
                if (!first) response.push_back(',');
                first = false;
                response += seeder.second.endpoint.ip + ":" +
                            std::to_string(seeder.second.endpoint.port) + ":" +
                            seeder.second.publicKey;
            }
            return {response, session, false};
        }
        if (command == "stop_share") {
            std::string group, encodedName, name;
            input >> group >> encodedName;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto groupIt = groups_.find(group);
            if (groupIt == groups_.end() || !hexDecode(encodedName, name)) return {"ERR invalid group/file", session, false};
            auto fileIt = groupIt->second.files.find(name);
            if (fileIt == groupIt->second.files.end() || !fileIt->second.seeders.erase(user))
                return replicated ? HandleResult{"OK already stopped", session, false}
                                  : HandleResult{"ERR you are not sharing this file", session, false};
            if (fileIt->second.seeders.empty()) groupIt->second.files.erase(fileIt);
            return {"OK sharing stopped", session, true};
        }
        return {"ERR unknown command", session, false};
    }
};

struct SyncItem {
    u64 session;
    std::string command;
};

class SyncQueue {
    Endpoint peer_;
    std::deque<SyncItem> queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool stopping_ = false;

public:
    explicit SyncQueue(Endpoint peer) : peer_(std::move(peer)) {}

    void enqueue(u64 session, const std::string &command) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return;
        queue_.push_back({session, command});
        condition_.notify_one();
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
        condition_.notify_all();
    }

    void run() {
        for (;;) {
            SyncItem item;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [&] { return stopping_ || !queue_.empty(); });
                if (stopping_) return;
                item = queue_.front();
            }
            int fd = connectTcp(peer_.ip, peer_.port, 2);
            bool delivered = false;
            if (fd >= 0) {
                std::string request = "S\t" + std::to_string(item.session) + "\t" + item.command;
                std::string response;
                delivered = sendFrame(fd, request) && receiveFrame(fd, response) &&
                            (response.rfind("OK", 0) == 0 || response == "REPLICATED");
                close(fd);
            }
            if (delivered) {
                std::lock_guard<std::mutex> lock(mutex_);
                queue_.pop_front();
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
};

inline void trackerConnection(int fd, TrackerState &state, SyncQueue &sync) {
    std::string request;
    if (!receiveFrame(fd, request)) {
        close(fd);
        return;
    }
    std::vector<std::string> fields = split(request, '\t');
    if (fields.size() >= 3 && fields[0] == "X" && fields[2] == "SNAPSHOT") {
        sendFrame(fd, "STATE\n" + state.serialize());
        close(fd);
        return;
    }
    if (fields.size() < 3 || (fields[0] != "C" && fields[0] != "S")) {
        sendFrame(fd, "ERR malformed request");
        close(fd);
        return;
    }
    u64 session = 0;
    try {
        session = static_cast<u64>(std::stoull(fields[1]));
    } catch (...) {
        sendFrame(fd, "ERR malformed session");
        close(fd);
        return;
    }
    std::string command = fields[2];
    for (std::size_t i = 3; i < fields.size(); ++i) command += "\t" + fields[i];
    bool replicated = fields[0] == "S";
    HandleResult result = state.handle(session, command, replicated);
    if (!replicated && result.shouldSync) {
        // Logout removes the session locally, but the peer needs the old token to identify
        // which user's shares and session must be removed.
        u64 replicationSession = command == "logout" ? session : result.session;
        sync.enqueue(replicationSession, command);
    }
    std::string response = result.response + "\t" + std::to_string(result.session);
    sendFrame(fd, response);
    close(fd);
}

inline bool readTrackerInfo(const std::string &path, std::vector<Endpoint> &trackers) {
    std::ifstream input(path);
    if (!input) return false;
    std::string token;
    while (input >> token) {
        std::string ip;
        int port = 0;
        std::size_t colon = token.rfind(':');
        if (colon != std::string::npos) {
            ip = token.substr(0, colon);
            try { port = std::stoi(token.substr(colon + 1)); } catch (...) { return false; }
        } else {
            ip = token;
            if (!(input >> port)) return false;
        }
        trackers.push_back({ip, port});
    }
    return trackers.size() == 2;
}

inline int runTracker(int argc, char **argv, unsigned defaultNumber) {
    std::vector<Endpoint> trackers;
    unsigned number = defaultNumber;
    if (argc == 3) {
        if (!readTrackerInfo(argv[1], trackers)) {
            std::cerr << "tracker info must contain exactly two IP:PORT entries\n";
            return 1;
        }
        try { number = static_cast<unsigned>(std::stoul(argv[2])); } catch (...) { number = 0; }
        if (number < 1 || number > 2) {
            std::cerr << "tracker number must be 1 or 2\n";
            return 1;
        }
    } else if (argc == 5) {
        trackers.push_back({argv[1], std::stoi(argv[2])});
        trackers.push_back({argv[3], std::stoi(argv[4])});
        if (defaultNumber == 2) std::swap(trackers[0], trackers[1]);
        number = defaultNumber;
    } else {
        std::cerr << "usage: " << argv[0] << " tracker_info.txt tracker_no\n";
        return 1;
    }

    Endpoint local = trackers[number - 1];
    Endpoint peer = trackers[2 - number];
    TrackerState state(number);
    if (state.empty()) {
        int peerFd = connectTcp(peer.ip, peer.port, 2);
        if (peerFd >= 0) {
            std::string snapshot;
            if (sendFrame(peerFd, "X\t0\tSNAPSHOT") && receiveFrame(peerFd, snapshot) &&
                snapshot.rfind("STATE\n", 0) == 0 &&
                state.replaceFromSnapshot(snapshot.substr(6))) {
                std::cerr << "Recovered current in-memory state from running peer\n";
            }
            close(peerFd);
        }
    }
    int listener = createListener(local.ip, local.port);
    if (listener < 0) {
        perror("tracker listen");
        return 1;
    }
    SyncQueue sync(peer);
    std::thread syncThread(&SyncQueue::run, &sync);
    std::cerr << "Tracker " << number << " listening on " << local.ip << ':' << local.port
              << ", peer " << peer.ip << ':' << peer.port << '\n';

    bool running = true;
    bool monitorConsole = true;
    std::mutex workersMutex;
    std::condition_variable workersCondition;
    std::size_t activeWorkers = 0;

    while (running) {
        pollfd descriptors[2]{};
        descriptors[0].fd = listener;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = monitorConsole ? STDIN_FILENO : -1;
        descriptors[1].events = POLLIN;
        int ready = poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (monitorConsole && (descriptors[1].revents & (POLLIN | POLLHUP))) {
            std::string command;
            if (!std::getline(std::cin, command)) monitorConsole = false;
            else if (command == "quit") running = false;
        }
        if (!running) break;
        if (descriptors[0].revents & POLLIN) {
            int client = accept(listener, nullptr, nullptr);
            if (client < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                break;
            }
            timeval timeout{};
            timeout.tv_sec = 5;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            {
                std::lock_guard<std::mutex> lock(workersMutex);
                ++activeWorkers;
            }
            std::thread([&, client] {
                trackerConnection(client, state, sync);
                {
                    std::lock_guard<std::mutex> lock(workersMutex);
                    --activeWorkers;
                }
                workersCondition.notify_all();
            }).detach();
        }
    }
    close(listener);
    {
        std::unique_lock<std::mutex> lock(workersMutex);
        workersCondition.wait(lock, [&] { return activeWorkers == 0; });
    }
    sync.stop();
    syncThread.join();
    return 0;
}

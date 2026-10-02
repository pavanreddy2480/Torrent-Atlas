#pragma once

#include "../common/protocol.hpp"
#include "../common/secure_crypto.hpp"

#include <atomic>
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <map>
#include <memory>
#include <poll.h>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct SeederInfo {
    Endpoint endpoint;
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
        u64 parsedIterations = 0;
        if (!parseUnsignedDecimal(fields[1], parsedIterations) ||
            parsedIterations == 0 || parsedIterations > 1000000)
            return false;
        std::uint32_t iterations = static_cast<std::uint32_t>(parsedIterations);
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
        std::map<std::string, std::string> sortedUsers(users_.begin(), users_.end());
        for (const auto &entry : sortedUsers)
            output << "U " << hexEncode(entry.first) << ' ' << hexEncode(entry.second) << '\n';
        std::map<u64, std::string> sortedSessions(sessions_.begin(), sessions_.end());
        for (const auto &entry : sortedSessions)
            output << "S " << entry.first << ' ' << hexEncode(entry.second) << '\n';
        std::map<std::string, GroupInfo> sortedGroups(groups_.begin(), groups_.end());
        for (const auto &groupEntry : sortedGroups) {
            const GroupInfo &group = groupEntry.second;
            std::string encodedGroup = hexEncode(groupEntry.first);
            output << "G " << encodedGroup << ' ' << hexEncode(group.owner) << '\n';
            std::vector<std::string> members(group.members.begin(), group.members.end());
            std::sort(members.begin(), members.end());
            for (const auto &member : members)
                output << "M " << encodedGroup << ' ' << hexEncode(member) << '\n';
            std::vector<std::string> pending(group.pending.begin(), group.pending.end());
            std::sort(pending.begin(), pending.end());
            for (const auto &pending : pending)
                output << "R " << encodedGroup << ' ' << hexEncode(pending) << '\n';
            std::map<std::string, FileInfo> files(group.files.begin(), group.files.end());
            for (const auto &fileEntry : files) {
                const FileInfo &file = fileEntry.second;
                std::string encodedFile = hexEncode(fileEntry.first);
                output << "F " << encodedGroup << ' ' << encodedFile << ' ' << file.size << ' '
                       << file.fullHash << ' ' << file.capability << ' '
                       << (file.pieceHashes.empty() ? "-" : joinHashes(file.pieceHashes)) << '\n';
                std::map<std::string, SeederInfo> seeders(
                    file.seeders.begin(), file.seeders.end());
                for (const auto &seeder : seeders)
                    output << "D " << encodedGroup << ' ' << encodedFile << ' '
                           << hexEncode(seeder.first) << ' ' << hexEncode(seeder.second.endpoint.ip) << ' '
                           << seeder.second.endpoint.port << '\n';
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
                record >> std::ws;
                if (!record.eof() || !hexDecode(a, user) || user.empty() ||
                    !hexDecode(b, password) || password.empty()) return false;
                users[user] = password;
            } else if (type == 'S') {
                u64 session = 0;
                record >> session >> a;
                std::string user;
                record >> std::ws;
                if (!record.eof() || session == 0 || !hexDecode(a, user) ||
                    user.empty()) return false;
                sessions[session] = user;
            } else if (type == 'G') {
                record >> a >> b;
                std::string group, owner;
                record >> std::ws;
                if (!record.eof() || !hexDecode(a, group) || group.empty() ||
                    !hexDecode(b, owner) || owner.empty()) return false;
                groups[group].owner = owner;
            } else if (type == 'M' || type == 'R') {
                record >> a >> b;
                std::string group, user;
                record >> std::ws;
                if (!record.eof() || !hexDecode(a, group) || group.empty() ||
                    !hexDecode(b, user) || user.empty()) return false;
                if (type == 'M') groups[group].members.insert(user);
                else groups[group].pending.insert(user);
            } else if (type == 'F') {
                u64 size = 0;
                std::string capability;
                record >> a >> b >> size >> c >> capability >> d;
                std::string group, name;
                record >> std::ws;
                std::size_t expectedPieces = 0;
                std::vector<std::string> pieceHashes =
                    d == "-" ? std::vector<std::string>{} : split(d, ',');
                if (!record.eof() || !hexDecode(a, group) || group.empty() ||
                    !hexDecode(b, name) || name.empty() || !isSha1Hex(c) ||
                    !isHexInteger(capability, 64, 64) ||
                    !pieceCountForSize(size, expectedPieces) ||
                    pieceHashes.size() != expectedPieces ||
                    !std::all_of(pieceHashes.begin(), pieceHashes.end(), isSha1Hex))
                    return false;
                FileInfo &file = groups[group].files[name];
                file.size = size;
                file.fullHash = c;
                file.capability = capability;
                file.pieceHashes = std::move(pieceHashes);
            } else if (type == 'D') {
                int port = 0;
                record >> a >> b >> c >> d >> port;
                std::string group, name, user, ip;
                record >> std::ws;
                Endpoint endpoint;
                if (!record.eof() || !hexDecode(a, group) || group.empty() ||
                    !hexDecode(b, name) || name.empty() ||
                    !hexDecode(c, user) || user.empty() ||
                    !hexDecode(d, ip) ||
                    !parseEndpoint(ip + ":" + std::to_string(port), endpoint))
                    return false;
                groups[group].files[name].seeders[user] = {{ip, port}};
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
        auto noExtraTokens = [&] {
            input >> std::ws;
            return input.eof();
        };

        std::lock_guard<std::mutex> lock(mutex_);
        std::string user;
        auto sessionIt = sessions_.find(session);
        if (sessionIt != sessions_.end()) user = sessionIt->second;
        auto requireLogin = [&]() -> bool { return !user.empty(); };

        if (command == "create_user") {
            std::string name, password;
            input >> name >> password;
            if (name.empty() || password.empty() || !noExtraTokens()) return {"ERR usage: create_user <user> <password>", session, false};
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
            if (name.empty() || password.empty() || !noExtraTokens()) {
                secureErase(password);
                return {"ERR usage: login <user> <password>", session, false};
            }
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
            if (!noExtraTokens()) return {"ERR usage: logout", session, false};
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
            if (group.empty() || !noExtraTokens()) return {"ERR usage: create_group <group>", session, false};
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
            if (group.empty() || !noExtraTokens()) return {"ERR usage: join_group <group>", session, false};
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
            if (group.empty() || !noExtraTokens()) return {"ERR usage: leave_group <group>", session, false};
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
            if (!noExtraTokens()) return {"ERR usage: list_groups", session, false};
            std::string response = "OK";
            std::vector<std::string> names;
            names.reserve(groups_.size());
            for (const auto &entry : groups_) names.push_back(entry.first);
            std::sort(names.begin(), names.end());
            for (const auto &name : names) response += " " + name;
            return {response, session, false};
        }
        if (command == "list_requests") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty() || !noExtraTokens()) return {"ERR usage: list_requests <group>", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (it->second.owner != user) return {"ERR only owner may list requests", session, false};
            std::string response = "OK";
            std::vector<std::string> pending(it->second.pending.begin(),
                                             it->second.pending.end());
            std::sort(pending.begin(), pending.end());
            for (const auto &name : pending) response += " " + name;
            return {response, session, false};
        }
        if (command == "accept_request") {
            std::string group, name;
            input >> group >> name;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty() || name.empty() || !noExtraTokens()) return {"ERR usage: accept_request <group> <user>", session, false};
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
            std::string group, encodedName, fullHash, capability, hashes, ip;
            u64 size = 0;
            int port = 0;
            input >> group >> encodedName >> size >> fullHash >> capability >> hashes >> ip >> port;
            std::string name;
            std::string capabilityBytes;
            if (!requireLogin()) return {"ERR login required", session, false};
            auto groupIt = groups_.find(group);
            if (groupIt == groups_.end()) return {"ERR no such group", session, false};
            if (!groupIt->second.members.count(user)) return {"ERR not a group member", session, false};
            Endpoint seederEndpoint;
            if (!noExtraTokens() || !hexDecode(encodedName, name) ||
                !hexDecode(capability, capabilityBytes) ||
                name.empty() || !isSha1Hex(fullHash) ||
                capability.size() != 64 ||
                !parseEndpoint(ip + ":" + std::to_string(port), seederEndpoint) ||
                capabilityBytes.size() != 32)
                return {"ERR invalid upload metadata", session, false};
            std::vector<std::string> pieceHashes = hashes == "-" ? std::vector<std::string>{} : split(hashes, ',');
            std::size_t expectedPieces = 0;
            if (!pieceCountForSize(size, expectedPieces) ||
                pieceHashes.size() != expectedPieces)
                return {"ERR invalid piece hash count", session, false};
            for (const auto &hash : pieceHashes)
                if (!isSha1Hex(hash)) return {"ERR invalid piece hash", session, false};

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
            file.seeders[user] = {seederEndpoint};
            return {"OK file shared " + file.capability, session, true};
        }
        if (command == "list_files") {
            std::string group;
            input >> group;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty() || !noExtraTokens()) return {"ERR usage: list_files <group>", session, false};
            auto it = groups_.find(group);
            if (it == groups_.end()) return {"ERR no such group", session, false};
            if (!it->second.members.count(user)) return {"ERR not a group member", session, false};
            std::string response = "OK";
            std::vector<std::string> files;
            files.reserve(it->second.files.size());
            for (const auto &entry : it->second.files) files.push_back(entry.first);
            std::sort(files.begin(), files.end());
            for (const auto &name : files) response += " " + hexEncode(name);
            return {response, session, false};
        }
        if (command == "download_file") {
            std::string group, encodedName, name;
            input >> group >> encodedName;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty() || encodedName.empty() || !noExtraTokens()) return {"ERR usage: download_file <group> <file>", session, false};
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
            std::vector<std::string> seederEndpoints;
            seederEndpoints.reserve(file.seeders.size());
            for (const auto &seeder : file.seeders)
                seederEndpoints.push_back(endpointKey(seeder.second.endpoint));
            std::sort(seederEndpoints.begin(), seederEndpoints.end());
            for (const auto &endpoint : seederEndpoints) {
                if (!first) response.push_back(',');
                first = false;
                response += endpoint;
            }
            return {response, session, false};
        }
        if (command == "stop_share") {
            std::string group, encodedName, name;
            input >> group >> encodedName;
            if (!requireLogin()) return {"ERR login required", session, false};
            if (group.empty() || encodedName.empty() || !noExtraTokens()) return {"ERR usage: stop_share <group> <file>", session, false};
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

// Cluster layout: node 1 is the write server, nodes 2 and 3 are read servers.
// Every mutation runs on the write server, gets the next sequence number, and
// is pushed synchronously to each in-sync read server before the client gets
// its answer. A read server that misses a sequence (it was down, restarted, or
// rejected an entry) is brought back by a full snapshot push.
static constexpr unsigned TRACKER_NODES = 3;
static constexpr unsigned WRITE_NODE = 1;

inline bool parseU64(const std::string &text, u64 &value) {
    return parseUnsignedDecimal(text, value);
}

inline std::string commandFromFields(const std::vector<std::string> &fields,
                                     std::size_t first) {
    std::string command = fields[first];
    for (std::size_t i = first + 1; i < fields.size(); ++i)
        command += "\t" + fields[i];
    return command;
}

// Read-server side: applies the write server's ordered stream.
class ReplicaLog {
    TrackerState &state_;
    std::mutex mutex_;
    u64 applied_ = 0;

public:
    explicit ReplicaLog(TrackerState &state) : state_(state) {}

    // Returns APPLIED, DUPLICATE, or RESYNC (gap or conflict; the write
    // server answers RESYNC with a snapshot push).
    std::string receive(u64 sequence, u64 session, const std::string &command) {
        if (sequence == 0) return "ERR malformed replication sequence";
        std::lock_guard<std::mutex> lock(mutex_);
        if (sequence <= applied_) return "DUPLICATE";
        if (sequence != applied_ + 1) return "RESYNC";
        HandleResult result = state_.handle(session, command, true);
        if (result.response.rfind("ERR", 0) == 0) {
            std::cerr << "Read server rejected sequence " << sequence
                      << "; requesting snapshot\n";
            return "RESYNC";
        }
        applied_ = sequence;
        return "APPLIED";
    }

    std::string install(u64 sequence, const std::string &snapshot) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!state_.replaceFromSnapshot(snapshot)) return "ERR invalid snapshot";
        applied_ = sequence;
        return "APPLIED";
    }

    u64 applied() {
        std::lock_guard<std::mutex> lock(mutex_);
        return applied_;
    }

    std::string snapshot() {
        std::lock_guard<std::mutex> lock(mutex_);
        return "SNAPSHOT\t" + std::to_string(applied_) + "\n" + state_.serialize();
    }
};

// Write-server side: owns the sequence and keeps both read servers in sync.
class WriteReplicator {
    TrackerState &state_;
    std::vector<Endpoint> readers_;
    std::vector<bool> inSync_;
    std::atomic<u64> sequence_{0};
    std::atomic<bool> recovered_{false};
    std::mutex stopMutex_;
    std::condition_variable stopCondition_;
    bool stopping_ = false;

    // Caller holds mutationMutex.
    bool pushSnapshot(std::size_t reader) {
        std::string response;
        bool ok = trackerCall(readers_[reader],
                              "P\t" + std::to_string(sequence_.load()) + "\n" +
                                  state_.serialize(),
                              response) &&
                  response == "APPLIED";
        if (ok)
            std::cerr << "Read server " << endpointKey(readers_[reader])
                      << " synced to sequence " << sequence_.load() << '\n';
        return ok;
    }

    static bool readSequence(const std::string &header, const char *kind, u64 &value) {
        std::vector<std::string> fields = split(header, '\t');
        return fields.size() >= 2 && fields[0] == kind && parseU64(fields[1], value);
    }

    // On start the write server has no state of its own. It takes the most
    // advanced read server's snapshot, or starts empty if every reachable
    // read server is empty. It needs at least one read server to answer.
    bool tryRecover() {
        bool anyAnswered = false;
        u64 bestSequence = 0;
        std::string bestState;
        std::vector<std::optional<u64>> readerSequence(readers_.size());
        for (std::size_t reader = 0; reader < readers_.size(); ++reader) {
            std::string response;
            if (!trackerCall(readers_[reader], "X\t0\tSNAPSHOT", response)) continue;
            std::size_t newline = response.find('\n');
            u64 sequence = 0;
            if (newline == std::string::npos ||
                !readSequence(response.substr(0, newline), "SNAPSHOT", sequence))
                continue;
            anyAnswered = true;
            readerSequence[reader] = sequence;
            if (sequence > bestSequence || bestState.empty()) {
                bestSequence = sequence;
                bestState = response.substr(newline + 1);
            }
        }
        if (!anyAnswered) return false;
        std::lock_guard<std::mutex> lock(mutationMutex);
        if (bestSequence > 0 && !state_.replaceFromSnapshot(bestState)) return false;
        sequence_ = bestSequence;
        for (std::size_t reader = 0; reader < readers_.size(); ++reader)
            inSync_[reader] = readerSequence[reader] == bestSequence;
        recovered_ = true;
        std::cerr << "Write server recovered at sequence " << bestSequence << '\n';
        return true;
    }

    void syncReaders() {
        for (std::size_t reader = 0; reader < readers_.size(); ++reader) {
            std::string response;
            u64 applied = 0;
            bool reachable = trackerCall(readers_[reader], "X\t0\tSTATUS", response) &&
                             readSequence(response.substr(response.find('\t') + 1),
                                          "replica", applied);
            std::lock_guard<std::mutex> lock(mutationMutex);
            if (!reachable) {
                inSync_[reader] = false;
            } else if (applied != sequence_) {
                inSync_[reader] = pushSnapshot(reader);
            } else {
                inSync_[reader] = true;
            }
        }
    }

public:
    std::mutex mutationMutex;

    WriteReplicator(TrackerState &state, std::vector<Endpoint> readers)
        : state_(state), readers_(std::move(readers)), inSync_(readers_.size(), false) {}

    bool recovered() const { return recovered_; }
    u64 sequence() const { return sequence_; }

    // Caller holds mutationMutex and has already applied the command locally.
    void replicate(u64 session, const std::string &command) {
        u64 sequence = ++sequence_;
        std::string frame = "S\t" + std::to_string(sequence) + "\t" +
                            std::to_string(session) + "\t" + command;
        for (std::size_t reader = 0; reader < readers_.size(); ++reader) {
            if (!inSync_[reader]) continue;
            std::string response;
            if (!trackerCall(readers_[reader], frame, response)) {
                inSync_[reader] = false;
                std::cerr << "Read server " << endpointKey(readers_[reader])
                          << " unreachable; will resync\n";
            } else if (response != "APPLIED" && response != "DUPLICATE") {
                inSync_[reader] = pushSnapshot(reader);
            }
        }
    }

    std::string snapshot() {
        std::lock_guard<std::mutex> lock(mutationMutex);
        return "SNAPSHOT\t" + std::to_string(sequence_.load()) + "\n" +
               state_.serialize();
    }

    void stop() {
        std::lock_guard<std::mutex> lock(stopMutex_);
        stopping_ = true;
        stopCondition_.notify_all();
    }

    void run() {
        for (;;) {
            if (!recovered_) tryRecover();
            else syncReaders();
            std::unique_lock<std::mutex> lock(stopMutex_);
            if (stopCondition_.wait_for(lock, std::chrono::milliseconds(250),
                                        [&] { return stopping_; }))
                return;
        }
    }
};

struct TrackerNode {
    unsigned number = 0;
    TrackerState &state;
    WriteReplicator *writer = nullptr;   // set on the write server
    ReplicaLog *replica = nullptr;       // set on read servers

    std::string status() const {
        if (writer)
            return std::string("STATUS\tprimary\t") + std::to_string(writer->sequence()) +
                   "\t" + (writer->recovered() ? "READY" : "RECOVERING");
        return "STATUS\treplica\t" + std::to_string(replica->applied()) + "\tREADY";
    }
};

inline void trackerConnection(int rawFd, TrackerNode &node) {
    UniqueFd fd(rawFd);
    std::string request;
    if (!receiveFrame(fd.get(), request)) return;

    // Snapshot push from the write server: "P\t<sequence>\n<state>".
    if (node.replica && request.rfind("P\t", 0) == 0) {
        std::size_t newline = request.find('\n');
        u64 sequence = 0;
        if (newline == std::string::npos ||
            !parseU64(request.substr(2, newline - 2), sequence)) {
            sendFrame(fd.get(), "ERR malformed snapshot push");
            return;
        }
        sendFrame(fd.get(), node.replica->install(sequence, request.substr(newline + 1)));
        return;
    }

    std::vector<std::string> fields = split(request, '\t');
    if (fields.size() == 3 && fields[0] == "X" && fields[2] == "STATUS") {
        sendFrame(fd.get(), node.status());
        return;
    }
    if (fields.size() == 3 && fields[0] == "X" && fields[2] == "SNAPSHOT") {
        sendFrame(fd.get(), node.writer ? node.writer->snapshot() : node.replica->snapshot());
        return;
    }
    if (fields.size() >= 4 && fields[0] == "S") {
        u64 sequence = 0, session = 0;
        if (!node.replica) {
            sendFrame(fd.get(), "ERR not a read server");
        } else if (!parseU64(fields[1], sequence) || !parseU64(fields[2], session)) {
            sendFrame(fd.get(), "ERR malformed replication frame");
        } else {
            sendFrame(fd.get(), node.replica->receive(sequence, session,
                                                      commandFromFields(fields, 3)));
        }
        return;
    }
    if (fields.size() < 3 || fields[0] != "C") {
        sendFrame(fd.get(), "ERR malformed request");
        return;
    }
    u64 session = 0;
    if (!parseU64(fields[1], session)) {
        sendFrame(fd.get(), "ERR malformed session");
        return;
    }
    std::string command = commandFromFields(fields, 2);
    HandleResult result;
    if (node.replica) {
        result = isTrackerMutation(command)
            ? HandleResult{"ERR read-only server; send writes to the write server", session, false}
            : node.state.handle(session, command, false);
    } else if (!node.writer->recovered()) {
        result = {"ERR write server recovering", session, false};
    } else {
        std::lock_guard<std::mutex> mutationLock(node.writer->mutationMutex);
        result = node.state.handle(session, command, false);
        if (result.shouldSync)
            node.writer->replicate(command == "logout" ? session : result.session, command);
    }
    sendFrame(fd.get(), result.response + "\t" + std::to_string(result.session));
}

inline bool readTrackerInfo(const std::string &path, std::vector<Endpoint> &trackers) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<Endpoint> loaded;
    std::string token;
    while (input >> token) {
        Endpoint endpoint;
        if (!parseEndpoint(token, endpoint)) return false;
        loaded.push_back(endpoint);
    }
    if (loaded.size() != TRACKER_NODES) return false;
    for (std::size_t i = 0; i < loaded.size(); ++i)
        for (std::size_t j = i + 1; j < loaded.size(); ++j)
            if (endpointKey(loaded[i]) == endpointKey(loaded[j])) return false;
    trackers = std::move(loaded);
    return true;
}

inline int runTracker(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " trackers.conf <1|2|3>\n";
        return 1;
    }
    std::vector<Endpoint> trackers;
    if (!readTrackerInfo(argv[1], trackers)) {
        std::cerr << "tracker config must list three distinct IP:PORT entries: "
                     "the write server, then two read servers\n";
        return 1;
    }
    u64 parsedNumber = 0;
    if (!parseUnsignedDecimal(argv[2], parsedNumber) || parsedNumber < 1 ||
        parsedNumber > TRACKER_NODES) {
        std::cerr << "tracker number must be 1 (write) or 2-3 (read)\n";
        return 1;
    }
    unsigned number = static_cast<unsigned>(parsedNumber);
    Endpoint local = trackers[number - 1];

    TrackerState state(number);
    std::unique_ptr<WriteReplicator> writer;
    std::unique_ptr<ReplicaLog> replica;
    if (number == WRITE_NODE)
        writer.reset(new WriteReplicator(
            state, std::vector<Endpoint>(trackers.begin() + 1, trackers.end())));
    else
        replica.reset(new ReplicaLog(state));
    TrackerNode node{number, state, writer.get(), replica.get()};

    int listener = createListener(local.ip, local.port);
    if (listener < 0) {
        perror("tracker listen");
        return 1;
    }
    std::thread syncThread;
    if (writer) syncThread = std::thread(&WriteReplicator::run, writer.get());
    std::cerr << "Tracker " << number << " ("
              << (writer ? "write server" : "read server") << ") listening on "
              << endpointKey(local) << '\n';

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
                trackerConnection(client, node);
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
    if (writer) {
        writer->stop();
        syncThread.join();
    }
    return 0;
}

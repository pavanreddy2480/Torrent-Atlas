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
#include <map>
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

struct SyncItem {
    unsigned origin = 0;
    u64 sequence = 0;
    u64 session;
    std::string command;
};

class ReplicationManager {
    TrackerState &state_;
    Endpoint peer_;
    std::deque<SyncItem> queue_;
    std::array<std::map<u64, SyncItem>, 2> pending_;
    std::array<u64, 2> applied_{};
    unsigned origin_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool stopping_ = false;
    bool degraded_ = false;

    bool deliver(const SyncItem &item) {
        UniqueFd fd(connectTcp(peer_.ip, peer_.port, 2));
        if (!fd) return false;
        std::string request = "S\t" + std::to_string(item.origin) + "\t" +
                              std::to_string(item.sequence) + "\t" +
                              std::to_string(item.session) + "\t" + item.command;
        std::string response;
        if (!sendFrame(fd.get(), request) || !receiveFrame(fd.get(), response))
            return false;
        return response == "APPLIED" || response == "DUPLICATE" ||
               response == "QUEUED" || response == "DEGRADED";
    }

    bool applyOne(const SyncItem &item) {
        HandleResult result = state_.handle(item.session, item.command, true);
        applied_[item.origin - 1] = item.sequence;
        if (result.response.rfind("ERR", 0) == 0) {
            degraded_ = true;
            std::cerr << "Tracker replica degraded after replication conflict from "
                      << item.origin << ':' << item.sequence << '\n';
            return false;
        }
        return true;
    }

public:
    std::mutex localMutationMutex;

    ReplicationManager(TrackerState &state, Endpoint peer, unsigned origin,
                       std::array<u64, 2> applied)
        : state_(state), peer_(std::move(peer)), applied_(applied),
          origin_(origin) {}

    void localCommitted(u64 session, const std::string &command) {
        SyncItem item;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            item = {origin_, ++applied_[origin_ - 1], session, command};
        }
        if (deliver(item)) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!stopping_) {
            queue_.push_back(std::move(item));
            condition_.notify_one();
        }
    }

    std::string receive(unsigned origin, u64 sequence, u64 session,
                        const std::string &command) {
        if (origin < 1 || origin > 2 || sequence == 0)
            return "ERR malformed replication sequence";
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t index = origin - 1;
        if (sequence <= applied_[index]) return "DUPLICATE";
        SyncItem item{origin, sequence, session, command};
        if (sequence != applied_[index] + 1) {
            pending_[index].emplace(sequence, std::move(item));
            return "QUEUED";
        }
        if (!applyOne(item)) return "DEGRADED";
        while (!degraded_) {
            auto next = pending_[index].find(applied_[index] + 1);
            if (next == pending_[index].end()) break;
            SyncItem queued = std::move(next->second);
            pending_[index].erase(next);
            if (!applyOne(queued)) return "DEGRADED";
        }
        return degraded_ ? "DEGRADED" : "APPLIED";
    }

    std::array<u64, 2> appliedVector() {
        std::lock_guard<std::mutex> lock(mutex_);
        return applied_;
    }

    bool degraded() {
        std::lock_guard<std::mutex> lock(mutex_);
        return degraded_;
    }

    std::string status() {
        std::lock_guard<std::mutex> lock(mutex_);
        return "STATUS\t" + std::to_string(applied_[0]) + "\t" +
               std::to_string(applied_[1]) + "\t" +
               (degraded_ ? "DEGRADED" : "READY");
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
            bool delivered = deliver(item);
            if (delivered) {
                std::lock_guard<std::mutex> lock(mutex_);
                queue_.pop_front();
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
};

inline bool parseU64(const std::string &text, u64 &value) {
    return parseUnsignedDecimal(text, value);
}

inline void trackerConnection(int rawFd, TrackerState &state,
                              ReplicationManager &replication) {
    UniqueFd fd(rawFd);
    std::string request;
    if (!receiveFrame(fd.get(), request)) return;
    std::vector<std::string> fields = split(request, '\t');
    if (fields.size() == 3 && fields[0] == "X" && fields[2] == "STATUS") {
        sendFrame(fd.get(), replication.status());
        return;
    }
    if (fields.size() == 3 && fields[0] == "X" && fields[2] == "SNAPSHOT") {
        auto applied = replication.appliedVector();
        sendFrame(fd.get(), "SNAPSHOT\t" + std::to_string(applied[0]) +
                            "\t" + std::to_string(applied[1]) + "\t" +
                            (replication.degraded() ? "DEGRADED" : "READY") +
                            "\n" + state.serialize());
        return;
    }
    if (fields.size() >= 5 && fields[0] == "S") {
        u64 originValue = 0, sequence = 0, session = 0;
        if (!parseU64(fields[1], originValue) || originValue < 1 ||
            originValue > 2 || !parseU64(fields[2], sequence) ||
            !parseU64(fields[3], session)) {
            sendFrame(fd.get(), "ERR malformed replication frame");
            return;
        }
        std::string command = fields[4];
        for (std::size_t i = 5; i < fields.size(); ++i)
            command += "\t" + fields[i];
        sendFrame(fd.get(), replication.receive(
            static_cast<unsigned>(originValue), sequence, session, command));
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
    std::string command = fields[2];
    for (std::size_t i = 3; i < fields.size(); ++i) command += "\t" + fields[i];
    HandleResult result;
    {
        std::lock_guard<std::mutex> mutationLock(replication.localMutationMutex);
        result = state.handle(session, command, false);
        if (result.shouldSync) {
            u64 replicationSession = command == "logout" ? session : result.session;
            replication.localCommitted(replicationSession, command);
        }
    }
    std::string response = result.response + "\t" + std::to_string(result.session);
    sendFrame(fd.get(), response);
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
    if (loaded.size() != 2 ||
        (loaded[0].ip == loaded[1].ip &&
         loaded[0].port == loaded[1].port))
        return false;
    trackers = std::move(loaded);
    return true;
}

inline int runTracker(int argc, char **argv, unsigned defaultNumber) {
    std::vector<Endpoint> trackers;
    unsigned number = defaultNumber;
    if (argc == 3) {
        if (!readTrackerInfo(argv[1], trackers)) {
            std::cerr << "tracker info must contain exactly two IP:PORT entries\n";
            return 1;
        }
        u64 parsedNumber = 0;
        if (!parseUnsignedDecimal(argv[2], parsedNumber) ||
            parsedNumber < 1 || parsedNumber > 2) {
            std::cerr << "tracker number must be 1 or 2\n";
            return 1;
        }
        number = static_cast<unsigned>(parsedNumber);
    } else {
        std::cerr << "usage: " << argv[0] << " tracker_info.txt tracker_no\n";
        return 1;
    }

    Endpoint local = trackers[number - 1];
    Endpoint peer = trackers[2 - number];
    TrackerState state(number);
    std::array<u64, 2> applied{};
    if (state.empty()) {
        UniqueFd peerFd(connectTcp(peer.ip, peer.port, 2));
        if (peerFd) {
            std::string snapshot;
            if (sendFrame(peerFd.get(), "X\t0\tSNAPSHOT") &&
                receiveFrame(peerFd.get(), snapshot)) {
                std::size_t newline = snapshot.find('\n');
                std::vector<std::string> header = split(
                    snapshot.substr(0, newline), '\t');
                u64 first = 0, second = 0;
                if (newline != std::string::npos && header.size() == 4 &&
                    header[0] == "SNAPSHOT" && header[3] == "READY" &&
                    parseU64(header[1], first) && parseU64(header[2], second) &&
                    state.replaceFromSnapshot(snapshot.substr(newline + 1))) {
                    applied = {first, second};
                    std::cerr << "Recovered sequence-aware in-memory snapshot from peer\n";
                }
            }
        }
    }
    int listener = createListener(local.ip, local.port);
    if (listener < 0) {
        perror("tracker listen");
        return 1;
    }
    ReplicationManager replication(state, peer, number, applied);
    std::thread syncThread(&ReplicationManager::run, &replication);
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
                trackerConnection(client, state, replication);
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
    replication.stop();
    syncThread.join();
    return 0;
}

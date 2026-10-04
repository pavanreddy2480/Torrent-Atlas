#pragma once

#include "../common/protocol.hpp"
#include "../common/secure_crypto.hpp"

#include <atomic>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
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

// Everything random or time-dependent that a command needs. On a Raft
// cluster the leader fills this in once and stores it in the log entry, so
// every replica applies the command identically.
struct ApplyContext {
    std::string salt;       // 16 bytes, used by create_user
    u64 newSession = 0;     // used by login
    long long now = 0;      // unix seconds, used by the login lockout

    static ApplyContext fresh() {
        ApplyContext context;
        context.salt = randomBytes(16);
        std::string bytes = randomBytes(sizeof(u64));
        if (bytes.size() == sizeof(u64))
            std::memcpy(&context.newSession, bytes.data(), sizeof(u64));
        context.newSession &= 0x7fffffffffffffffULL;
        context.now = static_cast<long long>(std::time(nullptr));
        return context;
    }
};

struct HandleResult {
    std::string response;
    u64 session = 0;
    bool shouldSync = false;
};

class TrackerState {
    struct LoginThrottle {
        unsigned failures = 0;
        long long lockedUntil = 0;
    };

    std::mutex mutex_;
    std::unordered_map<std::string, std::string> users_;
    std::unordered_map<u64, std::string> sessions_;
    std::unordered_map<std::string, GroupInfo> groups_;
    std::unordered_map<std::string, LoginThrottle> loginThrottles_;
    static constexpr std::uint32_t PASSWORD_ITERATIONS = 20000;

    static std::string encodePassword(const std::string &password,
                                      const std::string &salt) {
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
    TrackerState() = default;
    explicit TrackerState(unsigned) {}

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
        std::map<std::string, LoginThrottle> sortedThrottles(loginThrottles_.begin(),
                                                             loginThrottles_.end());
        for (const auto &entry : sortedThrottles)
            output << "T " << hexEncode(entry.first) << ' ' << entry.second.failures << ' '
                   << entry.second.lockedUntil << '\n';
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
        std::unordered_map<std::string, LoginThrottle> throttles;
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
            } else if (type == 'T') {
                LoginThrottle throttle;
                record >> a >> throttle.failures >> throttle.lockedUntil;
                std::string user;
                record >> std::ws;
                if (!record.eof() || !hexDecode(a, user) || user.empty()) return false;
                throttles[user] = throttle;
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
            loginThrottles_ = std::move(throttles);
        }
        return true;
    }

    HandleResult handle(u64 session, const std::string &commandLine, bool replicated) {
        return handle(session, commandLine, replicated, ApplyContext::fresh());
    }

    HandleResult handle(u64 session, const std::string &commandLine, bool replicated,
                        const ApplyContext &context) {
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
            std::string encoded = encodePassword(password, context.salt);
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
            const long long now = context.now;
            if (throttle.lockedUntil > now) {
                secureErase(password);
                return {"ERR too many login attempts; try again later", session, false};
            }
            bool passwordValid = verifyPassword(password, users_[name]);
            secureErase(password);
            if (!passwordValid) {
                if (++throttle.failures >= 5) {
                    throttle.failures = 0;
                    throttle.lockedUntil = now + 30;
                    return {"ERR too many login attempts; try again later", session, false};
                }
                return {"ERR invalid password", session, false};
            }
            loginThrottles_.erase(name);
            if (session == 0) {
                session = context.newSession;
                if (session == 0 || sessions_.count(session))
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

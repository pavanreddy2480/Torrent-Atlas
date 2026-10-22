#include "tracker/state/tracker_state.hpp"

#include "tracker/state/password.hpp"

#include "common/crypto/crypto.hpp"
#include "common/net/freshness.hpp"
#include "common/peer_ticket.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <sstream>

// The session ID is masked to 63 bits so it also fits a signed 64-bit
// integer wherever it is read.
ApplyContext ApplyContext::fresh() {
    ApplyContext context;
    context.salt = crypto::randomBytes(16);
    std::string bytes = crypto::randomBytes(sizeof(u64));
    if (bytes.size() == sizeof(u64)) std::memcpy(&context.newSession, bytes.data(), sizeof(u64));
    context.newSession &= 0x7fffffffffffffffULL;
    context.now = unixSeconds();
    return context;
}

const std::map<std::string, TrackerState::Command> &TrackerState::commands() {
    static const std::map<std::string, Command> table = {
        {"create_user", {&TrackerState::createUser, false, true, 2, "create_user <user> <password>"}},
        {"login", {&TrackerState::login, false, true, 2, "login <user> <password>"}},
        {"logout", {&TrackerState::logout, false, true, 0, "logout"}},
        {"create_group", {&TrackerState::createGroup, true, true, 1, "create_group <group>"}},
        {"join_group", {&TrackerState::joinGroup, true, true, 1, "join_group <group>"}},
        {"leave_group", {&TrackerState::leaveGroup, true, true, 1, "leave_group <group>"}},
        {"list_groups", {&TrackerState::listGroups, true, false, 0, "list_groups"}},
        {"list_requests", {&TrackerState::listRequests, true, false, 1, "list_requests <group>"}},
        {"accept_request",
         {&TrackerState::acceptRequest, true, true, 2, "accept_request <group> <user>"}},
        {"remove_member",
         {&TrackerState::removeMember, true, true, 2, "remove_member <group> <user>"}},
        {"upload_file", {&TrackerState::uploadFile, true, true, -1, "upload_file"}},
        {"list_files", {&TrackerState::listFiles, true, false, 1, "list_files <group>"}},
        {"download_file",
         {&TrackerState::downloadFile, true, false, 2, "download_file <group> <file>"}},
        {"stop_share", {&TrackerState::stopShare, true, true, 2, "stop_share <group> <file>"}},
    };
    return table;
}

bool TrackerState::isMutation(const std::string &commandLine) {
    std::string name;
    std::istringstream(commandLine) >> name;
    auto command = commands().find(name);
    return command != commands().end() && command->second.mutates;
}

// Splits the line into words, looks the command up, enforces login and
// arity from the table, then calls the handler with the lock held.
CommandResult TrackerState::apply(u64 session, const std::string &commandLine,
                                  const ApplyContext &context) {
    std::istringstream input(commandLine);
    std::vector<std::string> words;
    for (std::string word; input >> word;) words.push_back(word);
    if (words.empty()) return {"ERR empty command", session};

    std::lock_guard<std::mutex> lock(mutex_);
    auto command = commands().find(words[0]);
    if (command == commands().end()) return {"ERR unknown command", session};
    auto loggedIn = data_.sessions.find(session);
    Request request{session, loggedIn == data_.sessions.end() ? "" : loggedIn->second,
                    std::vector<std::string>(words.begin() + 1, words.end()), context};
    const Command &spec = command->second;
    if (spec.needsLogin && request.user.empty()) return request.reply("ERR login required");
    if (spec.arity >= 0 && request.args.size() != static_cast<std::size_t>(spec.arity))
        return request.reply(std::string("ERR usage: ") + spec.usage);
    return (this->*spec.handler)(request);
}

TrackerState::Group *TrackerState::findGroup(const std::string &name) {
    auto group = data_.groups.find(name);
    return group == data_.groups.end() ? nullptr : &group->second;
}

void TrackerState::Group::removeSharesOf(const std::string &user) {
    for (auto file = files.begin(); file != files.end();) {
        file->second.seeders.erase(user);
        file = file->second.seeders.empty() ? files.erase(file) : std::next(file);
    }
}

CommandResult TrackerState::createUser(Request &request) {
    const std::string &name = request.args[0];
    std::string &secret = request.args[1];
    if (data_.users.count(name)) return request.reply("ERR user already exists");
    std::string stored = password::hash(secret, request.context.salt);
    crypto::secureErase(secret);
    if (stored.empty()) return request.reply("ERR secure random generation failed");
    data_.users[name] = std::move(stored);
    return request.reply("OK user created");
}

CommandResult TrackerState::login(Request &request) {
    const std::string &name = request.args[0];
    std::string &secret = request.args[1];
    if (!request.user.empty()) return request.reply("ERR logout before logging in again");
    auto user = data_.users.find(name);
    if (user == data_.users.end()) return request.reply("ERR no such user");

    // Five wrong passwords lock the account for 30 seconds.
    LoginThrottle &throttle = data_.throttles[name];
    const long long now = request.context.now;
    if (throttle.lockedUntil > now)
        return request.reply("ERR too many login attempts; try again later");
    bool valid = password::verify(secret, user->second);
    crypto::secureErase(secret);
    if (!valid) {
        if (++throttle.failures < 5) return request.reply("ERR invalid password");
        throttle.failures = 0;
        throttle.lockedUntil = now + 30;
        return request.reply("ERR too many login attempts; try again later");
    }
    data_.throttles.erase(name);

    u64 session = request.session;
    if (session == 0) {
        session = request.context.newSession;
        if (session == 0 || data_.sessions.count(session))
            return {"ERR secure random generation failed", 0};
    }
    data_.sessions[session] = name;
    return {"OK logged in", session};
}

CommandResult TrackerState::logout(Request &request) {
    if (request.user.empty()) return request.reply("ERR not logged in");
    for (auto &group : data_.groups) group.second.removeSharesOf(request.user);
    data_.sessions.erase(request.session);
    return {"OK logged out", 0};
}

CommandResult TrackerState::createGroup(Request &request) {
    const std::string &name = request.args[0];
    if (data_.groups.count(name)) return request.reply("ERR group already exists");
    Group &group = data_.groups[name];
    group.owner = request.user;
    group.members.insert(request.user);
    return request.reply("OK group created");
}

CommandResult TrackerState::joinGroup(Request &request) {
    Group *group = findGroup(request.args[0]);
    if (!group) return request.reply("ERR no such group");
    if (group->members.count(request.user)) return request.reply("ERR already a member");
    if (!group->pending.insert(request.user).second)
        return request.reply("ERR request already pending");
    return request.reply("OK join requested");
}

CommandResult TrackerState::leaveGroup(Request &request) {
    Group *group = findGroup(request.args[0]);
    if (!group) return request.reply("ERR no such group");
    if (group->owner == request.user) return request.reply("ERR owner cannot leave group");
    if (!group->members.erase(request.user)) return request.reply("ERR not a member");
    group->removeSharesOf(request.user);
    return request.reply("OK left group");
}

CommandResult TrackerState::listGroups(Request &request) {
    std::string response = "OK";
    for (const auto &group : data_.groups) response += " " + group.first;
    return request.reply(response);
}

CommandResult TrackerState::listRequests(Request &request) {
    Group *group = findGroup(request.args[0]);
    if (!group) return request.reply("ERR no such group");
    if (group->owner != request.user) return request.reply("ERR only owner may list requests");
    std::string response = "OK";
    for (const std::string &user : group->pending) response += " " + user;
    return request.reply(response);
}

CommandResult TrackerState::acceptRequest(Request &request) {
    Group *group = findGroup(request.args[0]);
    const std::string &user = request.args[1];
    if (!group) return request.reply("ERR no such group");
    if (group->owner != request.user) return request.reply("ERR only owner may accept requests");
    if (!group->pending.erase(user)) return request.reply("ERR no such pending request");
    group->members.insert(user);
    return request.reply("OK request accepted");
}

// The removed user gets no more peer tickets for this group's files, and
// stops being offered as a seeder.
CommandResult TrackerState::removeMember(Request &request) {
    Group *group = findGroup(request.args[0]);
    const std::string &user = request.args[1];
    if (!group) return request.reply("ERR no such group");
    if (group->owner != request.user) return request.reply("ERR only owner may remove members");
    if (user == group->owner) return request.reply("ERR owner cannot be removed");
    if (!group->members.erase(user)) return request.reply("ERR not a member");
    group->removeSharesOf(user);
    return request.reply("OK member removed");
}

// upload_file <group> <hex name> <size> <SHA-1> <piece hashes> <ip> <port> <hex peer key>
CommandResult TrackerState::uploadFile(Request &request) {
    const std::vector<std::string> &args = request.args;
    Group *group = findGroup(args.empty() ? "" : args[0]);
    if (!group) return request.reply("ERR no such group");
    if (!group->members.count(request.user)) return request.reply("ERR not a group member");

    std::string name;
    FileMetadata metadata;
    std::optional<Endpoint> endpoint;
    std::string peerKey;
    if (args.size() == 8) {
        metadata.fullHash = args[3];
        metadata.pieceHashes = FileMetadata::parsePieceHashList(args[4]);
        endpoint = Endpoint::parse(args[5] + ":" + args[6]);
    }
    if (args.size() != 8 || !fromHex(args[1], name) || name.empty() ||
        !parseU64(args[2], metadata.size) || !metadata.valid() || !endpoint ||
        !fromHex(args[7], peerKey) || peerKey.size() != 32)
        return request.reply("ERR invalid upload metadata");

    SharedFile &file = group->files[name];
    if (file.metadata.fullHash.empty()) file.metadata = metadata;
    else if (!file.metadata.sameContent(metadata))
        return request.reply("ERR conflicting file metadata");
    file.seeders[request.user] = {*endpoint, peerKey};
    return request.reply("OK file shared");
}

CommandResult TrackerState::listFiles(Request &request) {
    Group *group = findGroup(request.args[0]);
    if (!group) return request.reply("ERR no such group");
    if (!group->members.count(request.user)) return request.reply("ERR not a group member");
    std::string response = "OK";
    for (const auto &file : group->files) response += " " + toHex(file.first);
    return request.reply(response);
}

// Replies "META <size> <SHA-1> <piece hashes> <seeder>,<seeder>...", where each
// seeder is a SeederAccess: its address, a fresh ticket and that ticket's key.
CommandResult TrackerState::downloadFile(Request &request) {
    Group *group = findGroup(request.args[0]);
    std::string name;
    if (!group) return request.reply("ERR no such group");
    if (!group->members.count(request.user)) return request.reply("ERR not a group member");
    if (!fromHex(request.args[1], name)) return request.reply("ERR invalid file name");
    auto file = group->files.find(name);
    if (file == group->files.end() || file->second.seeders.empty())
        return request.reply("ERR file has no online seeders");

    const FileMetadata &metadata = file->second.metadata;
    PeerTicket ticket{request.user, request.args[0], name,
                      request.context.now + PeerTicket::LIFETIME_SECONDS};
    std::vector<std::string> seeders;
    for (const auto &[user, seeder] : file->second.seeders) {
        SeederAccess access{seeder.endpoint, ticket.encode(), ticket.key(seeder.peerKey)};
        if (access.key.empty()) return request.reply("ERR could not issue peer tickets");
        seeders.push_back(access.encode());
    }
    std::sort(seeders.begin(), seeders.end());
    return request.reply("META " + std::to_string(metadata.size) + " " + metadata.fullHash + " " +
                         metadata.pieceHashList() + " " + join(seeders, ','));
}

CommandResult TrackerState::stopShare(Request &request) {
    Group *group = findGroup(request.args[0]);
    std::string name;
    if (!group || !fromHex(request.args[1], name)) return request.reply("ERR invalid group/file");
    auto file = group->files.find(name);
    if (file == group->files.end() || !file->second.seeders.erase(request.user))
        return request.reply("ERR you are not sharing this file");
    if (file->second.seeders.empty()) group->files.erase(file);
    return request.reply("OK sharing stopped");
}

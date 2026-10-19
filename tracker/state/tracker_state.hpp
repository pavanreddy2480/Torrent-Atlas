#pragma once

// The tracker's data: users, sessions, groups and the files shared in them.
// Every client command is applied here. On a Raft cluster each node holds one
// TrackerState and applies the same committed commands in the same order.

#include "common/file_metadata.hpp"
#include "common/net/net.hpp"

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

// Everything random or time-dependent that a command needs. On a Raft
// cluster the leader fills this in once and stores it in the log entry, so
// every replica applies the command identically.
struct ApplyContext {
    std::string salt;     // 16 bytes, used by create_user
    u64 newSession = 0;   // used by login
    long long now = 0;    // unix seconds, used by the login lockout

    static ApplyContext fresh();
};

struct CommandResult {
    std::string response;   // "OK ...", "ERR ..." or "META ..."
    u64 session = 0;        // the client's session after the command
};

class TrackerState {
public:
    // True for commands that change state; only those go through the Raft log.
    static bool isMutation(const std::string &commandLine);

    CommandResult apply(u64 session, const std::string &commandLine,
                        const ApplyContext &context = ApplyContext::fresh());

    // A deterministic text snapshot of everything, and its inverse.
    std::string serialize() const;
    bool restore(const std::string &snapshot);

private:
    struct SharedFile {
        FileMetadata metadata;
        std::map<std::string, Endpoint> seeders;   // user -> peer address
    };
    struct Group {
        std::string owner;
        std::set<std::string> members;
        std::set<std::string> pending;
        std::map<std::string, SharedFile> files;

        void removeSharesOf(const std::string &user);
    };
    struct LoginThrottle {
        u64 failures = 0;
        long long lockedUntil = 0;
    };
    struct Data {
        std::map<std::string, std::string> users;   // user -> stored password
        std::map<u64, std::string> sessions;        // session -> user
        std::map<std::string, Group> groups;
        std::map<std::string, LoginThrottle> throttles;
    };

    struct Request {
        u64 session;
        std::string user;   // empty when not logged in
        std::vector<std::string> args;
        const ApplyContext &context;

        CommandResult reply(std::string text) const { return {std::move(text), session}; }
    };
    using Handler = CommandResult (TrackerState::*)(Request &);
    struct Command {
        Handler handler;
        bool needsLogin;
        bool mutates;
        int arity;           // number of arguments, or -1 to let the handler check
        const char *usage;
    };
    static const std::map<std::string, Command> &commands();

    CommandResult createUser(Request &request);
    CommandResult login(Request &request);
    CommandResult logout(Request &request);
    CommandResult createGroup(Request &request);
    CommandResult joinGroup(Request &request);
    CommandResult leaveGroup(Request &request);
    CommandResult listGroups(Request &request);
    CommandResult listRequests(Request &request);
    CommandResult acceptRequest(Request &request);
    CommandResult uploadFile(Request &request);
    CommandResult listFiles(Request &request);
    CommandResult downloadFile(Request &request);
    CommandResult stopShare(Request &request);

    Group *findGroup(const std::string &name);

    mutable std::mutex mutex_;
    Data data_;
};

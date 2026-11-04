#pragma once

/// @file tracker_state.hpp
/// The tracker's data and every command that reads or changes it: users,
/// sessions, login lockouts, groups, members, join requests, and the files
/// shared in each group with their seeders.
///
/// Everything lives in memory: restarting the tracker starts it empty.
/// Passwords are kept only as PBKDF2 hashes.

#include "common/file_metadata.hpp"
#include "common/net/net.hpp"

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

/// Everything random or time-dependent that a command needs. Passing it in
/// (instead of calling the clock or RNG inside commands) lets tests pin the
/// time and check exact results.
struct ApplyContext {
    std::string salt;     ///< 16 random bytes; used by create_user.
    u64 newSession = 0;   ///< Random 63-bit session ID; used by login.
    long long now = 0;    ///< Unix seconds; ticket expiry.

    /// @return A context with a fresh random salt and session ID and the
    ///         current time. The salt is empty if the RNG failed, which
    ///         makes create_user fail cleanly.
    static ApplyContext fresh();
};

/// The outcome of one command.
struct CommandResult {
    std::string response;   ///< "OK ...", "ERR ..." or "META ..." for the client.
    u64 session = 0;        ///< The client's session after the command (0 = logged out).
};

/// Holds all tracker data and applies client commands to it.
///
/// Thread-safe: apply() and userOf() take an internal lock, so concurrent
/// callers see each command as atomic.
///
/// Commands (one line, space-separated words; file names travel hex-encoded):
///   create_user <user> <password>        login <user> <password>     logout
///   create_group <group>                 join_group <group>          leave_group <group>
///   list_groups                          list_requests <group>       accept_request <group> <user>
///   remove_member <group> <user>         list_files <group>          stop_share <group> <file>
///   upload_file <group> <file> <size> <SHA-1> <piece hashes> <ip> <port> <peer key>
///   download_file <group> <file>
/// Each answers "OK ...", "ERR <reason>", or (download_file) "META ...".
class TrackerState {
public:
    /// Runs one client command.
    /// @param session     The caller's session ID, or 0 if not logged in.
    ///                    Unknown IDs are treated as not logged in.
    /// @param commandLine The command and its arguments.
    /// @param context     Randomness and time to use (see ApplyContext).
    /// @return The reply text and the caller's session afterwards. Errors
    ///         are reported in the reply ("ERR ..."); this never throws.
    CommandResult apply(u64 session, const std::string &commandLine,
                        const ApplyContext &context = ApplyContext::fresh());

    /// @param session A session ID.
    /// @return The user logged in with it, or "" if none.
    std::string userOf(u64 session) const;

private:
    /// One seeder of a file.
    struct Seeder {
        Endpoint endpoint;     ///< Its peer server.
        std::string peerKey;   ///< Raw 32 bytes; see peer_ticket.hpp.
    };
    /// One file shared in a group.
    struct SharedFile {
        FileMetadata metadata;
        std::map<std::string, Seeder> seeders;   ///< user -> seeder
    };
    struct Group {
        std::string owner;
        std::set<std::string> members;   ///< Includes the owner.
        std::set<std::string> pending;   ///< Users waiting for accept_request.
        std::map<std::string, SharedFile> files;

        /// Drops user as a seeder of every file in this group, and drops
        /// files that are left with no seeders.
        void removeSharesOf(const std::string &user);
    };

    /// One command being applied, as handed to a handler.
    struct Request {
        u64 session;
        std::string user;   ///< Empty when not logged in.
        std::vector<std::string> args;   ///< The words after the command name.
        const ApplyContext &context;

        /// @return text as the reply, keeping the caller's session unchanged.
        CommandResult reply(std::string text) const { return {std::move(text), session}; }
    };
    /// A command handler; called with mutex_ held.
    using Handler = CommandResult (TrackerState::*)(Request &);
    /// The dispatch table's entry for one command.
    struct Command {
        Handler handler;
        bool needsLogin;     ///< Refuse with "ERR login required" if not logged in.
        int arity;           ///< Number of arguments, or -1 to let the handler check.
        const char *usage;   ///< Shown in "ERR usage: ..." on a wrong arity.
    };
    /// @return The table mapping each command name to its Command.
    static const std::map<std::string, Command> &commands();

    // Command handlers. Each checks its own permissions and arguments and
    // returns the reply; apply() has already checked login and arity.

    /// Adds a user with a hashed password. Erases the password argument.
    CommandResult createUser(Request &request);
    /// Checks the password and starts a session. A caller that sent a nonzero (unknown) session ID
    /// keeps it; otherwise context.newSession is used.
    CommandResult login(Request &request);
    /// Ends the session and stops all the user's shares.
    CommandResult logout(Request &request);
    /// Creates a group owned (and joined) by the caller.
    CommandResult createGroup(Request &request);
    /// Files a join request for the owner to accept.
    CommandResult joinGroup(Request &request);
    /// Leaves a group (not allowed for the owner) and drops the caller's shares in it.
    CommandResult leaveGroup(Request &request);
    /// Lists every group name.
    CommandResult listGroups(Request &request);
    /// Lists pending join requests; owner only.
    CommandResult listRequests(Request &request);
    /// Turns a pending request into membership; owner only.
    CommandResult acceptRequest(Request &request);
    /// Removes a member (not the owner) and their shares; owner only.
    CommandResult removeMember(Request &request);
    /// Registers the caller as a seeder of a file; members only. The first
    /// upload fixes the file's metadata; later ones must match it.
    CommandResult uploadFile(Request &request);
    /// Lists the group's files (hex names); members only.
    CommandResult listFiles(Request &request);
    /// Returns the file's metadata and a fresh ticket per seeder; members only.
    CommandResult downloadFile(Request &request);
    /// Stops the caller seeding a file; drops the file if no seeders remain.
    CommandResult stopShare(Request &request);

    /// @return The group, or nullptr if it does not exist. mutex_ held.
    Group *findGroup(const std::string &name);

    mutable std::mutex mutex_;   ///< Guards the three maps below.
    std::map<std::string, std::string> users_;   ///< user -> password::hash() string
    std::map<u64, std::string> sessions_;        ///< session -> user
    std::map<std::string, Group> groups_;
};

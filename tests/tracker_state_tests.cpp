#include "../tracker/log_command.hpp"
#include "../tracker/tracker_state.hpp"

#include <cassert>
#include <iostream>

int main() {
    TrackerState state;
    assert(state.apply(0, "create_user alice secret").response == "OK user created");

    std::string snapshot = state.serialize();
    assert(snapshot.find("secret") == std::string::npos);
    assert(snapshot.find(toHex("secret")) == std::string::npos);
    assert(snapshot.find("pbkdf2-sha256") == std::string::npos);   // hex-encoded

    CommandResult wrong = state.apply(0, "login alice incorrect");
    assert(wrong.response == "ERR invalid password" && wrong.session == 0);
    CommandResult login = state.apply(0, "login alice secret");
    assert(login.response == "OK logged in" && login.session != 0);
    u64 session = login.session;

    assert(state.apply(session, "create_group demo").response == "OK group created");
    assert(state.apply(session, "create_group alpha").response == "OK group created");
    assert(state.apply(session, "list_groups").response == "OK alpha demo");
    assert(state.apply(session, "list_groups trailing").response == "ERR usage: list_groups");
    assert(state.apply(session, "bogus").response == "ERR unknown command");
    assert(state.apply(session, "").response == "ERR empty command");
    std::string capability(64, 'a');
    assert(state.apply(session, "upload_file demo 66696c65 1 "
                                "0123456789abcdef0123456789abcdef0123456z " + capability +
                                " 0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000")
               .response == "ERR invalid upload metadata");
    assert(state.apply(session, "upload_file demo 66696c65 1 "
                                "0123456789abcdef0123456789abcdef01234567 " + capability +
                                " 0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000 extra")
               .response == "ERR invalid upload metadata");

    TrackerState replica;
    assert(replica.restore(state.serialize()));
    assert(replica.apply(0, "login alice secret").response == "OK logged in");

    TrackerState cleanRestart;
    assert(cleanRestart.apply(0, "login alice secret").response == "ERR no such user");

    // Five wrong passwords lock the account, even for the right password.
    assert(cleanRestart.apply(0, "create_user eve secret").response == "OK user created");
    for (int attempt = 0; attempt < 4; ++attempt)
        assert(cleanRestart.apply(0, "login eve wrong").response == "ERR invalid password");
    assert(cleanRestart.apply(0, "login eve wrong").response ==
           "ERR too many login attempts; try again later");
    assert(cleanRestart.apply(0, "login eve secret").response ==
           "ERR too many login attempts; try again later");

    // Access control: login required, members-only files, owner-only admin.
    {
        TrackerState acl;
        acl.apply(0, "create_user owner pw");
        acl.apply(0, "create_user outsider pw");
        u64 owner = acl.apply(0, "login owner pw").session;
        u64 outsider = acl.apply(0, "login outsider pw").session;
        assert(acl.apply(0, "create_group secret").response == "ERR login required");
        assert(acl.apply(owner, "create_group secret").response == "OK group created");
        std::string upload = "upload_file secret " + toHex("a.txt") +
                             " 0 0123456789abcdef0123456789abcdef01234567 " + capability +
                             " - 127.0.0.1 9000";
        assert(acl.apply(owner, upload).response == "OK file shared " + capability);
        assert(acl.apply(owner, "download_file secret " + toHex("a.txt")).response ==
               "META 0 0123456789abcdef0123456789abcdef01234567 " + capability +
                   " - 127.0.0.1:9000");
        assert(acl.apply(outsider, "list_files secret").response == "ERR not a group member");
        assert(acl.apply(outsider, "download_file secret " + toHex("a.txt")).response ==
               "ERR not a group member");
        assert(acl.apply(outsider, upload).response == "ERR not a group member");
        assert(acl.apply(outsider, "join_group secret").response == "OK join requested");
        assert(acl.apply(outsider, "join_group secret").response == "ERR request already pending");
        assert(acl.apply(outsider, "accept_request secret outsider").response ==
               "ERR only owner may accept requests");
        assert(acl.apply(outsider, "list_requests secret").response ==
               "ERR only owner may list requests");
        assert(acl.apply(owner, "list_requests secret").response == "OK outsider");
        assert(acl.apply(owner, "leave_group secret").response == "ERR owner cannot leave group");

        // Logging out stops sharing; the file disappears with its last seeder.
        assert(acl.apply(owner, "logout").session == 0);
        assert(acl.apply(owner, "logout").response == "ERR not logged in");
        u64 again = acl.apply(0, "login owner pw").session;
        assert(acl.apply(again, "list_files secret").response == "OK");
    }

    // Raft replicas must reach identical state from identical log entries:
    // all randomness and time come from the entry, not the replica.
    {
        ApplyContext first = ApplyContext::fresh();
        ApplyContext second = ApplyContext::fresh();
        second.now = first.now + 1;
        std::vector<LogCommand> log = {{0, first, "create_user carol secret"},
                                       {0, second, "login carol wrong"},
                                       {0, second, "login carol secret"}};
        TrackerState replicaA, replicaB;
        for (const LogCommand &entry : log) {
            std::optional<LogCommand> decoded = LogCommand::decode(entry.encode());
            assert(decoded && decoded->command == entry.command &&
                   decoded->context.salt == entry.context.salt &&
                   decoded->context.newSession == entry.context.newSession &&
                   decoded->context.now == entry.context.now);
            CommandResult a = replicaA.apply(decoded->session, decoded->command, decoded->context);
            CommandResult b = replicaB.apply(decoded->session, decoded->command, decoded->context);
            assert(a.response == b.response && a.session == b.session);
        }
        assert(replicaA.serialize() == replicaB.serialize());

        // Snapshots carry the login lockout too.
        TrackerState restored;
        assert(restored.restore(replicaA.serialize()));
        assert(restored.serialize() == replicaA.serialize());
        assert(!restored.restore("X junk\n"));
    }

    assert(TrackerState::isMutation("login alice secret"));
    assert(TrackerState::isMutation("upload_file demo x"));
    assert(!TrackerState::isMutation("list_files demo"));
    assert(!TrackerState::isMutation("download_file demo x"));

    std::cout << "tracker state tests passed\n";
}

#include "../tracker/raft_tracker.hpp"

#include <cassert>
#include <array>
#include <iostream>

int main() {
    TrackerState state(1);

    HandleResult created = state.handle(0, "create_user alice secret", false);
    assert(created.response == "OK user created");

    std::string snapshot = state.serialize();
    assert(snapshot.find("secret") == std::string::npos);
    assert(snapshot.find(hexEncode("secret")) == std::string::npos);
    assert(snapshot.find("pbkdf2-sha256") == std::string::npos);

    HandleResult wrong = state.handle(0, "login alice incorrect", false);
    assert(wrong.response == "ERR invalid password");
    assert(wrong.session == 0);

    HandleResult login = state.handle(0, "login alice secret", false);
    assert(login.response == "OK logged in");
    assert(login.session != 0);

    HandleResult group = state.handle(login.session, "create_group demo", false);
    assert(group.response == "OK group created");
    assert(state.handle(login.session, "create_group alpha", false).response ==
           "OK group created");
    assert(state.handle(login.session, "list_groups", false).response ==
           "OK alpha demo");
    assert(state.handle(login.session, "list_groups trailing", false).response ==
           "ERR usage: list_groups");
    std::string capability =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    assert(state.handle(
        login.session,
        "upload_file demo 66696c65 1 "
        "0123456789abcdef0123456789abcdef0123456z " + capability +
        " 0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000",
        false).response == "ERR invalid upload metadata");
    assert(state.handle(
        login.session,
        "upload_file demo 66696c65 1 "
        "0123456789abcdef0123456789abcdef01234567 " + capability +
        " 0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000 extra",
        false).response == "ERR invalid upload metadata");

    TrackerState replica(2);
    assert(replica.replaceFromSnapshot(state.serialize()));
    HandleResult replicaLogin = replica.handle(0, "login alice secret", false);
    assert(replicaLogin.response == "OK logged in");

    TrackerState cleanRestart(1);
    HandleResult missing = cleanRestart.handle(0, "login alice secret", false);
    assert(missing.response == "ERR no such user");

    assert(cleanRestart.handle(0, "create_user eve secret", false).response ==
           "OK user created");
    for (int attempt = 0; attempt < 4; ++attempt)
        assert(cleanRestart.handle(0, "login eve wrong", false).response ==
               "ERR invalid password");
    assert(cleanRestart.handle(0, "login eve wrong", false).response ==
           "ERR too many login attempts; try again later");
    assert(cleanRestart.handle(0, "login eve secret", false).response ==
           "ERR too many login attempts; try again later");

    // Raft replicas must reach identical state from identical log entries:
    // all randomness and time come from the entry, not the replica.
    {
        ApplyContext first = ApplyContext::fresh();
        ApplyContext second = ApplyContext::fresh();
        second.now = first.now + 1;
        std::vector<std::pair<std::string, ApplyContext>> log = {
            {"create_user carol secret", first},
            {"login carol wrong", second},
            {"login carol secret", second},
        };
        TrackerState replicaA, replicaB;
        for (const auto &entry : log) {
            u64 session = 0;
            ApplyContext decoded;
            std::string command;
            assert(decodeCommandEntry(encodeCommandEntry(0, entry.second, entry.first),
                                      session, decoded, command));
            assert(command == entry.first && decoded.salt == entry.second.salt &&
                   decoded.newSession == entry.second.newSession &&
                   decoded.now == entry.second.now);
            HandleResult a = replicaA.handle(session, command, false, decoded);
            HandleResult b = replicaB.handle(session, command, false, decoded);
            assert(a.response == b.response && a.session == b.session);
        }
        assert(replicaA.serialize() == replicaB.serialize());

        // Snapshots carry the login lockout too.
        TrackerState restored;
        assert(restored.replaceFromSnapshot(replicaA.serialize()));
        assert(restored.serialize() == replicaA.serialize());
    }

    assert(isTrackerMutation("login alice secret"));
    assert(isTrackerMutation("upload_file demo x"));
    assert(!isTrackerMutation("list_files demo"));
    assert(!isTrackerMutation("download_file demo x"));

    std::cout << "tracker state tests passed\n";
}

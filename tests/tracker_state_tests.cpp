#include "../tracker/tracker_common.hpp"

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
    assert((login.session >> 56U) == 1);

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
    assert((replicaLogin.session >> 56U) == 2);

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

    TrackerState ordered(2);
    ReplicaLog orderedReplica(ordered);
    assert(orderedReplica.receive(2, 0, "create_user bob secret") == "RESYNC");
    assert(orderedReplica.receive(1, 0, "create_user alice secret") == "APPLIED");
    assert(orderedReplica.receive(1, 0, "create_user alice secret") == "DUPLICATE");
    assert(orderedReplica.receive(2, 0, "create_user bob secret") == "APPLIED");
    assert(ordered.handle(0, "login alice secret", false).response ==
           "OK logged in");
    assert(ordered.handle(0, "login bob secret", false).response ==
           "OK logged in");
    assert(orderedReplica.applied() == 2);

    TrackerState conflicting(2);
    ReplicaLog conflictingReplica(conflicting);
    assert(conflictingReplica.receive(1, 0, "create_group demo") == "RESYNC");
    assert(conflictingReplica.applied() == 0);

    TrackerState source(1);
    assert(source.handle(0, "create_user carol secret", false).response ==
           "OK user created");
    assert(conflictingReplica.install(7, source.serialize()) == "APPLIED");
    assert(conflictingReplica.applied() == 7);
    assert(conflictingReplica.receive(8, 0, "create_user dave secret") == "APPLIED");
    assert(conflicting.handle(0, "login carol secret", false).response ==
           "OK logged in");
    assert(conflictingReplica.install(9, "not a snapshot") == "ERR invalid snapshot");
    assert(conflictingReplica.applied() == 8);

    assert(isTrackerMutation("login alice secret"));
    assert(isTrackerMutation("upload_file demo x"));
    assert(!isTrackerMutation("list_files demo"));
    assert(!isTrackerMutation("download_file demo x"));

    std::cout << "tracker state tests passed\n";
}

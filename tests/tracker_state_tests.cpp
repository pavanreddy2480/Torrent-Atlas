#include "../tracker/tracker_common.hpp"

#include <cassert>
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

    std::cout << "tracker state tests passed\n";
}

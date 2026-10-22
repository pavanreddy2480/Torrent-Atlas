/// @file tracker_state_tests.cpp
/// TrackerState without sockets: every command, access control, member
/// removal, ticket issue, login lockout and the saved-state round trip.
#include "tracker/state/tracker_state.hpp"

#include "common/peer_ticket.hpp"

#include <cassert>
#include <iostream>

/// @return true if the saved form of state contains text.
static bool serializedHas(const TrackerState &state, const std::string &text) {
    return state.serialize().find(text) != std::string::npos;
}

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
    std::string peerKey(32, 'k');
    std::string hexPeerKey = toHex(peerKey);
    assert(state.apply(session, "upload_file demo 66696c65 1 "
                                "0123456789abcdef0123456789abcdef0123456z "
                                "0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000 " +
                                hexPeerKey)
               .response == "ERR invalid upload metadata");
    assert(state.apply(session, "upload_file demo 66696c65 1 "
                                "0123456789abcdef0123456789abcdef01234567 "
                                "0123456789abcdef0123456789abcdef01234567 127.0.0.1 9000 abcd")
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
                             " 0 0123456789abcdef0123456789abcdef01234567 - 127.0.0.1 9000 " +
                             hexPeerKey;
        assert(acl.apply(owner, upload).response == "OK file shared");

        // download_file gives a ticket for the seeder, keyed with its peer key.
        ApplyContext at = ApplyContext::fresh();
        at.now = 1000;
        std::string meta = acl.apply(owner, "download_file secret " + toHex("a.txt"), at).response;
        PeerTicket ticket{"owner", "secret", "a.txt", 1000 + PeerTicket::LIFETIME_SECONDS};
        SeederAccess expected{*Endpoint::parse("127.0.0.1:9000"), ticket.encode(),
                              ticket.key(peerKey)};
        assert(meta == "META 0 0123456789abcdef0123456789abcdef01234567 - " + expected.encode());
        std::optional<SeederAccess> parsed = SeederAccess::decode(expected.encode());
        assert(parsed && parsed->key == expected.key && parsed->expires() == ticket.expires);
        assert(serializedHas(acl, hexPeerKey));
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

        // A removed member gets no more tickets and is no longer a seeder.
        assert(acl.apply(owner, "accept_request secret outsider").response == "OK request accepted");
        std::string outsiderUpload = "upload_file secret " + toHex("a.txt") +
                                     " 0 0123456789abcdef0123456789abcdef01234567 - 127.0.0.1 "
                                     "9001 " + toHex(std::string(32, 'o'));
        assert(acl.apply(outsider, outsiderUpload).response == "OK file shared");
        assert(acl.apply(outsider, "download_file secret " + toHex("a.txt")).response.rfind(
                   "META ", 0) == 0);
        assert(acl.apply(outsider, "remove_member secret owner").response ==
               "ERR only owner may remove members");
        assert(acl.apply(owner, "remove_member secret owner").response ==
               "ERR owner cannot be removed");
        assert(acl.apply(owner, "remove_member secret outsider").response == "OK member removed");
        assert(acl.apply(owner, "remove_member secret outsider").response == "ERR not a member");
        assert(acl.apply(outsider, "download_file secret " + toHex("a.txt")).response ==
               "ERR not a group member");
        assert(acl.apply(owner, "download_file secret " + toHex("a.txt")).response.find("9001") ==
               std::string::npos);

        // Logging out stops sharing; the file disappears with its last seeder.
        assert(acl.apply(owner, "logout").session == 0);
        assert(acl.apply(owner, "logout").response == "ERR not logged in");
        u64 again = acl.apply(0, "login owner pw").session;
        assert(acl.apply(again, "list_files secret").response == "OK");
    }

    // Snapshots carry the login lockout too.
    {
        TrackerState restored;
        assert(restored.restore(cleanRestart.serialize()));
        assert(restored.serialize() == cleanRestart.serialize());
        assert(restored.apply(0, "login eve secret").response ==
               "ERR too many login attempts; try again later");
        assert(!restored.restore("X junk\n"));
    }

    assert(TrackerState::isMutation("login alice secret"));
    assert(TrackerState::isMutation("upload_file demo x"));
    assert(!TrackerState::isMutation("list_files demo"));
    assert(TrackerState::isMutation("remove_member demo x"));
    assert(!TrackerState::isMutation("download_file demo x"));

    std::cout << "tracker state tests passed\n";
}

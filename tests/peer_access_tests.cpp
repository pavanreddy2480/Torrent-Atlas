/// @file peer_access_tests.cpp
/// The peer server only answers requests with a valid tracker ticket, and
/// gives one identical answer to everything else.
#include "client/peer/peer_protocol.hpp"
#include "client/peer/peer_server.hpp"

#include "common/net/freshness.hpp"
#include "common/peer_ticket.hpp"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <unistd.h>

namespace {

/// The seeder's peer key in these tests.
const std::string PEER_KEY(32, 'p');

// What a downloader holding (ticket, key) would get back for one request.
std::string ask(const PeerServer &server, const std::string &ticket, const std::string &key,
                const std::string &operation, std::size_t piece, std::string &plain) {
    std::string frame, nonce;
    assert(peer_protocol::makeRequest(ticket, key, operation, piece, frame, nonce));
    std::string reply = server.respond(frame);
    if (!peer_protocol::openReply(ticket, key, nonce, reply, plain)) plain.clear();
    return reply;
}

/// A ticket for bob to fetch file from group "demo", valid for the usual lifetime.
PeerTicket ticketFor(const std::string &file) {
    return {"bob", "demo", file, unixSeconds() + PeerTicket::LIFETIME_SECONDS};
}

}  // namespace

int main() {
    std::string path = "/tmp/torrent-peer-access-" + std::to_string(getpid());
    { std::ofstream(path) << "hello"; }
    FileMetadata metadata;
    metadata.size = 5;
    metadata.pieceHashes = {crypto::sha1Hex("hello")};
    metadata.fullHash = metadata.pieceHashes[0];
    SharedFiles files;
    files.add("demo", "shared.txt", {path, metadata, {true}});
    PeerServer server(files, PEER_KEY);
    std::string plain;

    // A ticket from the tracker works.
    PeerTicket valid = ticketFor("shared.txt");
    ask(server, valid.encode(), valid.key(PEER_KEY), "GET", 0, plain);
    assert(plain == "hello");
    assert(ask(server, valid.encode(), valid.key(PEER_KEY), "BITMAP", 0, plain).rfind("30|", 0) == 0);
    assert(plain == std::string(1, '\1'));
    assert(ask(server, valid.encode(), valid.key(PEER_KEY), "GET", 7, plain) ==
           peer_protocol::UNAVAILABLE);

    // Without this peer's key nobody can make a working ticket, however much
    // else they know: a guessed key, an edited ticket, or an expired one.
    std::string guessed = crypto::randomBytes(32);
    assert(ask(server, valid.encode(), guessed, "GET", 0, plain) == peer_protocol::DENIED);
    PeerTicket edited = valid;
    edited.user = "mallory";
    assert(ask(server, edited.encode(), valid.key(PEER_KEY), "GET", 0, plain) ==
           peer_protocol::DENIED);
    edited = valid;
    edited.expires += 3600;   // stretching the lifetime breaks the key
    assert(ask(server, edited.encode(), valid.key(PEER_KEY), "GET", 0, plain) ==
           peer_protocol::DENIED);
    PeerTicket expired = valid;
    expired.expires = unixSeconds() - 1;
    assert(ask(server, expired.encode(), expired.key(PEER_KEY), "GET", 0, plain) ==
           peer_protocol::DENIED);

    // A file this peer does not have looks exactly like a bad key on one it
    // does have, so a stranger cannot list what it shares.
    PeerTicket missing = ticketFor("missing.txt");
    assert(ask(server, missing.encode(), guessed, "GET", 0, plain) == peer_protocol::DENIED);
    assert(ask(server, missing.encode(), missing.key(PEER_KEY), "GET", 0, plain) ==
           peer_protocol::DENIED);
    assert(server.respond("garbage") == peer_protocol::DENIED);
    assert(server.respond("21|" + valid.encode() + "|00|00|00") == peer_protocol::DENIED);

    std::remove(path.c_str());
    std::cout << "peer access tests passed\n";
}

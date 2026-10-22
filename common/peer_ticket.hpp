#pragma once

// Peer access tickets: how a seeder knows the tracker allowed a download.
//
// Every seeder gives the tracker a random 32-byte peer key when it shares a
// file; nobody else ever sees it. When a group member asks the tracker for a
// file, the tracker writes one ticket per seeder:
//
//   ticket  "<hex user>.<hex group>.<hex file>.<expires unix seconds>"
//   key     HMAC-SHA256(that seeder's peer key, ticket)
//
// and hands both to the member over the encrypted tracker channel. The member
// sends the ticket in the clear and encrypts the request under the key. The
// seeder recomputes the key from its own peer key, so a ticket that the
// tracker did not issue, that was edited, or that has expired gets nothing.
//
// There is no long-lived file key: a ticket works for one user, one file and
// one seeder for a few minutes. Someone removed from a group (or who leaves)
// gets no new tickets, so they lose access as soon as their last one expires.

#include "common/net/net.hpp"

#include <optional>
#include <string>

struct PeerTicket {
    static constexpr long long LIFETIME_SECONDS = 300;

    std::string user;
    std::string group;
    std::string file;
    long long expires = 0;   // unix seconds

    std::string encode() const;
    static std::optional<PeerTicket> decode(const std::string &text);

    bool expired(long long now) const { return now >= expires; }
    // The 32-byte request key for this ticket at the seeder holding peerKey.
    std::string key(const std::string &peerKey) const;
};

// What a downloader gets from the tracker for one seeder.
struct SeederAccess {
    Endpoint endpoint;
    std::string ticket;   // PeerTicket::encode()
    std::string key;      // raw 32 bytes

    // "<ip:port>/<ticket>/<hex key>", as the tracker sends it.
    std::string encode() const;
    static std::optional<SeederAccess> decode(const std::string &text);
    long long expires() const;   // 0 if the ticket does not parse
};

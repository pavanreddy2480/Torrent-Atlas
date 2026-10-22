#pragma once

/// @file peer_ticket.hpp
/// Peer access tickets: how a seeder knows the tracker allowed a download.
///
/// Every seeder gives the tracker a random 32-byte peer key when it shares a
/// file; nobody else ever sees it. When a group member asks the tracker for a
/// file, the tracker writes one ticket per seeder:
///
///   ticket  "<hex user>.<hex group>.<hex file>.<expires unix seconds>"
///   key     HMAC-SHA256(that seeder's peer key, "torrent-peer-ticket-v1|" + ticket)
///
/// and hands both to the member over the encrypted tracker channel. The member
/// sends the ticket in the clear and encrypts the request under the key. The
/// seeder recomputes the key from its own peer key, so a ticket that the
/// tracker did not issue, that was edited, or that has expired gets nothing.
///
/// There is no long-lived file key: a ticket works for one user, one file and
/// one seeder for a few minutes. Someone removed from a group (or who leaves)
/// gets no new tickets, so they lose access as soon as their last one expires.

#include "common/net/net.hpp"

#include <optional>
#include <string>

/// The claims a ticket carries. A plain value type.
struct PeerTicket {
    /// How long a newly issued ticket stays valid.
    static constexpr long long LIFETIME_SECONDS = 300;

    std::string user;        ///< Who the ticket was issued to.
    std::string group;       ///< The group the file is shared in.
    std::string file;        ///< The file name within the group.
    long long expires = 0;   ///< Unix seconds; invalid from this moment on.

    /// @return The wire form "<hex user>.<hex group>.<hex file>.<expires>".
    ///         Hex keeps any name safe inside the '.'- and '|'-separated
    ///         protocols.
    std::string encode() const;

    /// Parses the wire form. Does not check expiry or authenticity.
    /// @return The ticket, or std::nullopt if any field is missing, empty
    ///         or malformed.
    static std::optional<PeerTicket> decode(const std::string &text);

    /// @param now Unix seconds.
    /// @return true once now has reached expires.
    bool expired(long long now) const { return now >= expires; }

    /// The request key for this ticket at the seeder holding peerKey.
    /// Any change to any field gives an unrelated key.
    /// @param peerKey The seeder's raw 32-byte peer key.
    /// @return 32 bytes, or "" if HMAC failed.
    std::string key(const std::string &peerKey) const;
};

/// What a downloader gets from the tracker for one seeder: where it is, the
/// ticket to show it, and the key to encrypt requests with.
struct SeederAccess {
    Endpoint endpoint;    ///< The seeder's peer server.
    std::string ticket;   ///< PeerTicket::encode() of this seeder's ticket.
    std::string key;      ///< Raw 32-byte request key for that ticket.

    /// @return "<ip:port>/<ticket>/<hex key>", as the tracker sends it.
    std::string encode() const;

    /// Parses the tracker's form.
    /// @return The access, or std::nullopt if the address, ticket or key is
    ///         invalid.
    static std::optional<SeederAccess> decode(const std::string &text);

    /// @return The ticket's expiry in Unix seconds, or 0 if it does not parse.
    long long expires() const;
};

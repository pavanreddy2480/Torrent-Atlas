#pragma once

/// @file peer_client.hpp
/// The downloader's side of the peer protocol.

#include "common/peer_ticket.hpp"

#include <string>
#include <vector>

/// The outcome of one request to a peer.
enum class TransferResult {
    Success,                 ///< Got a valid, authenticated reply (and a matching hash).
    NetworkFailure,          ///< Couldn't connect, or the connection broke.
    AuthenticationFailure,   ///< Denied, or the reply didn't decrypt or had the wrong shape.
    IntegrityFailure,        ///< A piece arrived but its SHA-1 was wrong.
    Unavailable              ///< The peer accepted the ticket but lacks that piece.
};

/// Requests a file's piece bitmap or pieces from its seeders (see
/// peer_protocol.hpp) using the tickets the tracker issued.
///
/// Stateless, so many download threads can share one PeerClient.
class PeerClient {
public:
    /// Asks a seeder which pieces it has.
    /// @param pieceCount The file's piece count; a reply of another length
    ///                   counts as an authentication failure.
    /// @param bitmap     Receives one flag per piece on success.
    /// @return Success, or why it failed.
    TransferResult fetchBitmap(const SeederAccess &seeder, std::size_t pieceCount,
                               std::vector<bool> &bitmap) const;

    /// Fetches one piece.
    /// @param expectedHash The piece's SHA-1 from the tracker.
    /// @param data         Receives the piece bytes.
    /// @return Success only if the piece arrived and matches expectedHash;
    ///         IntegrityFailure if it arrived but doesn't match.
    TransferResult fetchPiece(const SeederAccess &seeder, std::size_t index,
                              const std::string &expectedHash, std::string &data) const;

private:
    /// One request/reply exchange over a new connection.
    /// @param operation "BITMAP" or "GET".
    /// @param reply     Receives the decrypted reply.
    TransferResult request(const SeederAccess &seeder, const std::string &operation,
                           std::size_t piece, std::string &reply) const;
};

#pragma once

/// @file peer_client.hpp
/// The downloader's side of the peer protocol.

#include "client/peer/peer_stats.hpp"

#include "common/peer_ticket.hpp"

#include <string>
#include <vector>

/// Requests a file's piece bitmap or pieces from its seeders (see
/// peer_protocol.hpp) using the tickets the tracker issued, and records
/// every outcome in PeerStats.
///
/// Stateless apart from the stats it writes, so many download threads can
/// share one PeerClient.
class PeerClient {
public:
    /// @param stats Where every request's outcome is recorded. Must outlive
    ///              this object.
    explicit PeerClient(PeerStats &stats) : stats_(stats) {}

    /// Asks a seeder which pieces it has.
    /// @param pieceCount The file's piece count; a reply of another length
    ///                   counts as an authentication failure.
    /// @param bitmap     Receives one flag per piece on success.
    /// @return Success, or why it failed.
    TransferResult fetchBitmap(const SeederAccess &seeder, std::size_t pieceCount,
                               std::vector<bool> &bitmap);

    /// Fetches one piece.
    /// @param expectedHash The piece's SHA-1 from the tracker.
    /// @param data         Receives the piece bytes.
    /// @return Success only if the piece arrived and matches expectedHash;
    ///         IntegrityFailure if it arrived but doesn't match.
    TransferResult fetchPiece(const SeederAccess &seeder, std::size_t index,
                              const std::string &expectedHash, std::string &data);

private:
    /// One request/reply exchange over a new connection.
    /// @param operation "BITMAP" or "GET".
    /// @param reply     Receives the decrypted reply.
    /// @param seconds   Receives the time taken, for throughput stats.
    TransferResult request(const SeederAccess &seeder, const std::string &operation,
                           std::size_t piece, std::string &reply, double &seconds);

    PeerStats &stats_;
};

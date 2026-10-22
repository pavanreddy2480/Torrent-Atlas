#pragma once

// Requests a file's piece bitmap or pieces from its seeders (see
// peer_protocol.hpp), using the tickets the tracker issued, and records every
// outcome in PeerStats.

#include "client/peer/peer_stats.hpp"

#include "common/peer_ticket.hpp"

#include <string>
#include <vector>

class PeerClient {
public:
    explicit PeerClient(PeerStats &stats) : stats_(stats) {}

    TransferResult fetchBitmap(const SeederAccess &seeder, std::size_t pieceCount,
                               std::vector<bool> &bitmap);
    // Succeeds only if the piece matches expectedHash.
    TransferResult fetchPiece(const SeederAccess &seeder, std::size_t index,
                              const std::string &expectedHash, std::string &data);

private:
    TransferResult request(const SeederAccess &seeder, const std::string &operation,
                           std::size_t piece, std::string &reply, double &seconds);

    PeerStats &stats_;
};

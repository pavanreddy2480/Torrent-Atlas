#pragma once

// Requests one file's piece bitmap or pieces from its seeders (see
// peer_protocol.hpp), and records every outcome in PeerStats.

#include "client/peer/peer_stats.hpp"

#include "common/net/net.hpp"

#include <string>
#include <vector>

class PeerClient {
public:
    PeerClient(std::string group, std::string name, std::string capability, PeerStats &stats);

    TransferResult fetchBitmap(const Endpoint &peer, std::size_t pieceCount,
                               std::vector<bool> &bitmap);
    // Succeeds only if the piece matches expectedHash.
    TransferResult fetchPiece(const Endpoint &peer, std::size_t index,
                              const std::string &expectedHash, std::string &data);

private:
    TransferResult request(const Endpoint &peer, const std::string &operation, std::size_t piece,
                           std::string &reply, double &seconds);

    std::string group_;
    std::string name_;
    std::string capability_;
    PeerStats &stats_;
};

#pragma once

// Serves pieces of SharedFiles to other peers (see peer_protocol.hpp) on a
// background thread. Only requests carrying a ticket the tracker issued for
// this peer's key get an answer.

#include "client/storage/shared_files.hpp"

#include "common/net/tcp_server.hpp"

#include <thread>

class PeerServer {
public:
    // peerKey is this client's secret peer key (see peer_ticket.hpp).
    PeerServer(const SharedFiles &files, std::string peerKey);
    ~PeerServer() { stop(); }

    bool start(const Endpoint &endpoint);
    void stop();

    // The reply frame for one request frame.
    std::string respond(const std::string &request) const;

private:
    const SharedFiles &files_;
    const std::string peerKey_;
    TcpServer server_;
    std::thread thread_;
};

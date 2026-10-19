#pragma once

// Serves pieces of SharedFiles to other peers (see peer_protocol.hpp) on a
// background thread.

#include "shared_files.hpp"

#include "../common/tcp_server.hpp"

#include <thread>

class PeerServer {
public:
    explicit PeerServer(const SharedFiles &files);
    ~PeerServer() { stop(); }

    bool start(const Endpoint &endpoint);
    void stop();

    // The reply frame for one request frame.
    std::string respond(const std::string &request) const;

private:
    const SharedFiles &files_;
    TcpServer server_;
    std::thread thread_;
};

#pragma once

/// @file peer_server.hpp
/// Serves pieces of this client's SharedFiles to other peers.

#include "client/storage/shared_files.hpp"

#include "common/net/tcp_server.hpp"

#include <thread>

/// Answers other peers' BITMAP and GET requests (see peer_protocol.hpp) on a
/// background thread, one request per connection.
///
/// Only requests carrying an unexpired ticket the tracker issued for this
/// client's peer key get an answer. Every request that doesn't fully check
/// out gets the same "60|denied", so a stranger can't tell which files are
/// shared here.
class PeerServer {
public:
    /// @param files   What to serve. Must outlive the server.
    /// @param peerKey This client's secret raw 32-byte peer key.
    PeerServer(const SharedFiles &files, std::string peerKey);
    /// Stops the server and waits for it.
    ~PeerServer() { stop(); }

    /// Listens on endpoint and starts serving on a background thread.
    /// @return false if the address can't be bound.
    bool start(const Endpoint &endpoint);

    /// Stops accepting, waits for in-flight requests, and joins the thread.
    /// Safe to call more than once.
    void stop();

    /// Computes the reply to one request frame. Pure apart from reading
    /// files_ and the piece from disk; public so tests can call it without
    /// sockets.
    /// @param request A frame "21|<ticket>|<nonce>|<ciphertext>|<tag>".
    /// @return A "30|..." encrypted reply, "60|unavailable" for a valid
    ///         request this peer can't serve, or "60|denied" for anything else.
    std::string respond(const std::string &request) const;

private:
    const SharedFiles &files_;
    const std::string peerKey_;
    TcpServer server_;
    std::thread thread_;   ///< Runs server_.serve().
};

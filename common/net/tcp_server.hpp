#pragma once

/// @file tcp_server.hpp
/// A minimal thread-per-connection TCP server, used by the tracker and by
/// each client's peer server.

#include "common/net/net.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>

/// Accepts connections and runs a handler for each one on its own thread.
///
/// Lifecycle: listen() once, then serve() (blocks), and stop() from any
/// other thread to make serve() return. serve() waits for every running
/// handler to finish before it returns, so it is safe to destroy whatever
/// the handler uses once serve() is back.
class TcpServer {
public:
    /// Called once per accepted connection, on a new thread. The handler
    /// owns the socket; it is closed when the handler returns.
    using Handler = std::function<void(Socket)>;

    explicit TcpServer(Handler handler) : handler_(std::move(handler)) {}

    /// Binds and listens on endpoint.
    /// @return false if the address is invalid or already in use.
    bool listen(const Endpoint &endpoint);

    /// Accepts connections until stop() is called, then closes the listener
    /// and waits for in-flight handlers. Notices stop() within ~200 ms.
    void serve();

    /// Asks serve() to return. Thread-safe; may be called more than once.
    void stop() { stopping_ = true; }

private:
    Handler handler_;
    Socket listener_;
    std::atomic<bool> stopping_{false};
    std::mutex mutex_;                ///< Guards active_.
    std::condition_variable idle_;    ///< Signalled when a handler finishes.
    std::size_t active_ = 0;          ///< Handlers currently running.
};

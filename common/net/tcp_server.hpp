#pragma once

// Accepts connections and handles each one on its own thread. serve() blocks
// until stop() is called, then waits for the open connections to finish.

#include "common/net/net.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>

class TcpServer {
public:
    using Handler = std::function<void(Socket)>;

    explicit TcpServer(Handler handler) : handler_(std::move(handler)) {}

    bool listen(const Endpoint &endpoint);
    void serve();
    void stop() { stopping_ = true; }

private:
    Handler handler_;
    Socket listener_;
    std::atomic<bool> stopping_{false};
    std::mutex mutex_;
    std::condition_variable idle_;
    std::size_t active_ = 0;
};

#include "common/net/tcp_server.hpp"

#include <cerrno>
#include <poll.h>
#include <thread>

bool TcpServer::listen(const Endpoint &endpoint) {
    listener_ = Socket::listen(endpoint);
    return static_cast<bool>(listener_);
}

void TcpServer::serve() {
    while (!stopping_) {
        // Wake up regularly to notice stop().
        pollfd descriptor{listener_.fd(), POLLIN, 0};
        if (poll(&descriptor, 1, 200) <= 0) continue;
        Socket connection = listener_.accept();
        if (!connection) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            break;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++active_;
        }
        std::thread([this, connection = std::move(connection)]() mutable {
            handler_(std::move(connection));
            std::lock_guard<std::mutex> lock(mutex_);
            --active_;
            idle_.notify_all();
        }).detach();
    }
    listener_ = Socket();
    std::unique_lock<std::mutex> lock(mutex_);
    idle_.wait(lock, [this] { return active_ == 0; });
}

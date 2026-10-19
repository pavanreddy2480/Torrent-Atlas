#include "net.hpp"

#include "encoding.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

bool toAddress(const Endpoint &endpoint, sockaddr_in &address) {
    if (endpoint.port <= 0 || endpoint.port > 65535) return false;
    address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(endpoint.port));
    return inet_pton(AF_INET, endpoint.ip.c_str(), &address.sin_addr) == 1;
}

// Waits for a non-blocking connect() to finish.
bool waitForConnect(int fd, int timeoutSeconds) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
    for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() < 0) return false;
        pollfd descriptor{fd, POLLOUT, 0};
        int ready = poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        int error = 0;
        socklen_t length = sizeof(error);
        return getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
    }
}

}  // namespace

std::optional<Endpoint> Endpoint::parse(const std::string &text) {
    std::size_t colon = text.find(':');
    if (colon == std::string::npos || colon == 0 || text.find(':', colon + 1) != std::string::npos)
        return std::nullopt;
    Endpoint endpoint;
    endpoint.ip = text.substr(0, colon);
    u64 port = 0;
    sockaddr_in address{};
    if (!parseU64(text.substr(colon + 1), port) || port == 0 || port > 65535) return std::nullopt;
    endpoint.port = static_cast<int>(port);
    if (!toAddress(endpoint, address)) return std::nullopt;
    return endpoint;
}

Socket::~Socket() {
    if (fd_ >= 0) ::close(fd_);
}

Socket &Socket::operator=(Socket &&other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

Socket Socket::connect(const Endpoint &endpoint, int timeoutSeconds) {
    sockaddr_in address{};
    if (!toAddress(endpoint, address) || timeoutSeconds < 0) return {};
    Socket socket(::socket(AF_INET, SOCK_STREAM, 0));
    if (!socket) return {};
    int flags = fcntl(socket.fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(socket.fd_, F_SETFL, flags | O_NONBLOCK) < 0) return {};
    if (::connect(socket.fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0 &&
        (errno != EINPROGRESS || !waitForConnect(socket.fd_, timeoutSeconds)))
        return {};
    if (fcntl(socket.fd_, F_SETFL, flags) < 0) return {};
    socket.setTimeout(timeoutSeconds);
    return socket;
}

Socket Socket::listen(const Endpoint &endpoint, int backlog) {
    sockaddr_in address{};
    if (!toAddress(endpoint, address)) return {};
    Socket socket(::socket(AF_INET, SOCK_STREAM, 0));
    int enabled = 1;
    if (!socket ||
        setsockopt(socket.fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0 ||
        bind(socket.fd_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(socket.fd_, backlog) != 0)
        return {};
    return socket;
}

Socket Socket::accept() const { return Socket(::accept(fd_, nullptr, nullptr)); }

void Socket::setTimeout(int seconds) {
    timeval timeout{};
    timeout.tv_sec = seconds;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

bool Socket::sendAll(const void *data, std::size_t length) {
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    const char *cursor = static_cast<const char *>(data);
    while (length != 0) {
        ssize_t count = ::send(fd_, cursor, length, flags);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        length -= static_cast<std::size_t>(count);
    }
    return true;
}

bool Socket::receiveAll(void *data, std::size_t length) {
    char *cursor = static_cast<char *>(data);
    while (length != 0) {
        ssize_t count = ::recv(fd_, cursor, length, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        length -= static_cast<std::size_t>(count);
    }
    return true;
}

bool Socket::sendFrame(const std::string &payload) {
    if (payload.size() > MAX_FRAME) return false;
    std::uint32_t length = htonl(static_cast<std::uint32_t>(payload.size()));
    return sendAll(&length, sizeof(length)) && sendAll(payload.data(), payload.size());
}

bool Socket::receiveFrame(std::string &payload) {
    std::uint32_t length = 0;
    if (!receiveAll(&length, sizeof(length))) return false;
    length = ntohl(length);
    if (length > MAX_FRAME) return false;
    payload.resize(length);
    return receiveAll(payload.data(), length);
}

#pragma once

// TCP over IPv4. Every message is a frame: a 4-byte big-endian length, then
// that many bytes.

#include <optional>
#include <string>

struct Endpoint {
    std::string ip;
    int port = 0;

    // "IPv4:port", e.g. "127.0.0.1:5000".
    static std::optional<Endpoint> parse(const std::string &text);
    std::string toString() const { return ip + ":" + std::to_string(port); }
    bool operator==(const Endpoint &other) const {
        return ip == other.ip && port == other.port;
    }
};

// Owns a socket file descriptor and closes it when destroyed.
class Socket {
public:
    static constexpr std::size_t MAX_FRAME = 16U * 1024U * 1024U;

    Socket() = default;
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket();
    Socket(Socket &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    Socket &operator=(Socket &&other) noexcept;
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    // An invalid Socket on failure.
    static Socket connect(const Endpoint &endpoint, int timeoutSeconds = 5);
    static Socket listen(const Endpoint &endpoint, int backlog = 64);
    Socket accept() const;

    void setTimeout(int seconds);
    bool sendAll(const void *data, std::size_t length);
    bool sendFrame(const std::string &payload);
    bool receiveFrame(std::string &payload);

    int fd() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }

private:
    bool receiveAll(void *data, std::size_t length);

    int fd_ = -1;
};

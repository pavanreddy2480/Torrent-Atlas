#pragma once

/// @file net.hpp
/// Blocking TCP over IPv4 with message framing.
///
/// Every message on the wire is a *frame*: a 4-byte big-endian length
/// followed by that many bytes. Frames larger than Socket::MAX_FRAME are
/// refused on both send and receive, which caps how much memory a remote
/// peer can make us allocate.

#include <optional>
#include <string>

/// An IPv4 address and TCP port, e.g. 127.0.0.1:5000.
struct Endpoint {
    std::string ip;   ///< Dotted-quad IPv4 address.
    int port = 0;     ///< 1..65535 once parsed.

    /// Parses "IPv4:port".
    /// @param text e.g. "127.0.0.1:5000". Host names and IPv6 are not accepted.
    /// @return The endpoint, or std::nullopt if the address or port is invalid.
    static std::optional<Endpoint> parse(const std::string &text);

    /// @return "ip:port", the same form parse() accepts.
    std::string toString() const { return ip + ":" + std::to_string(port); }

    bool operator==(const Endpoint &other) const {
        return ip == other.ip && port == other.port;
    }
};

/// RAII owner of one socket file descriptor.
///
/// Move-only: the descriptor is closed exactly once, when the last owner is
/// destroyed or reassigned. A default-constructed or failed Socket is
/// "invalid" and converts to false. A Socket is not thread-safe; use each
/// one from a single thread.
class Socket {
public:
    /// Largest frame payload sendFrame()/receiveFrame() will handle (16 MiB).
    static constexpr std::size_t MAX_FRAME = 16U * 1024U * 1024U;

    /// Creates an invalid socket.
    Socket() = default;
    /// Takes ownership of an already-open descriptor (or -1 for invalid).
    explicit Socket(int fd) : fd_(fd) {}
    /// Closes the descriptor if valid.
    ~Socket();
    Socket(Socket &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    /// Closes the current descriptor, then takes other's.
    Socket &operator=(Socket &&other) noexcept;
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    /// Opens a TCP connection, waiting at most timeoutSeconds.
    /// The returned socket also gets timeoutSeconds as its send/receive
    /// timeout (see setTimeout()).
    /// @return A connected socket, or an invalid one on any failure
    ///         (bad endpoint, refused, unreachable, timed out).
    static Socket connect(const Endpoint &endpoint, int timeoutSeconds = 5);

    /// Binds to endpoint (with SO_REUSEADDR) and starts listening.
    /// @param backlog Maximum queue of not-yet-accepted connections.
    /// @return A listening socket, or an invalid one if the bind failed.
    static Socket listen(const Endpoint &endpoint, int backlog = 64);

    /// Blocks until a client connects to this listening socket.
    /// @return The new connection, or an invalid socket if accept() failed
    ///         (errno says why).
    Socket accept() const;

    /// Sets both the receive and the send timeout. After it, a send or
    /// receive that makes no progress for `seconds` fails instead of
    /// blocking forever. 0 means no timeout.
    void setTimeout(int seconds);

    /// Writes all `length` bytes, retrying partial writes and EINTR.
    /// Never raises SIGPIPE where the platform allows avoiding it.
    /// @return false if the connection failed or the send timed out.
    bool sendAll(const void *data, std::size_t length);

    /// Sends one frame (length prefix + payload).
    /// @return false if payload exceeds MAX_FRAME or the send failed.
    bool sendFrame(const std::string &payload);

    /// Receives one whole frame.
    /// @param payload Receives the frame's bytes (resized to fit).
    /// @return false on disconnect, timeout, or a length over MAX_FRAME.
    bool receiveFrame(std::string &payload);

    /// @return The raw descriptor, or -1 if invalid. Ownership stays here.
    int fd() const { return fd_; }
    /// @return true if this socket holds an open descriptor.
    explicit operator bool() const { return fd_ >= 0; }

private:
    /// Reads exactly `length` bytes, retrying partial reads and EINTR.
    /// @return false on disconnect or timeout before all bytes arrived.
    bool receiveAll(void *data, std::size_t length);

    int fd_ = -1;
};

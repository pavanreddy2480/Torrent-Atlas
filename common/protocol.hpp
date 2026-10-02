#pragma once

#include <arpa/inet.h>
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using u32 = std::uint32_t;
using u64 = std::uint64_t;

static const std::size_t MAX_FRAME = 16U * 1024U * 1024U;
static const std::size_t PIECE_SIZE = 512U * 1024U;

struct Endpoint {
    std::string ip;
    int port = 0;
};

class UniqueFd {
    int fd_ = -1;

public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() { reset(); }
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;
    UniqueFd(UniqueFd &&other) noexcept : fd_(other.release()) {}
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
    int release() {
        int value = fd_;
        fd_ = -1;
        return value;
    }
    void reset(int fd = -1) {
        if (fd_ >= 0) close(fd_);
        fd_ = fd;
    }
};

inline std::string endpointKey(const Endpoint &endpoint) {
    return endpoint.ip + ":" + std::to_string(endpoint.port);
}

inline bool parseUnsignedDecimal(const std::string &text, u64 &value) {
    if (text.empty()) return false;
    u64 parsed = 0;
    for (unsigned char character : text) {
        if (character < '0' || character > '9') return false;
        unsigned digit = character - '0';
        if (parsed > (std::numeric_limits<u64>::max() - digit) / 10U)
            return false;
        parsed = parsed * 10U + digit;
    }
    value = parsed;
    return true;
}

inline bool parseEndpoint(const std::string &text, Endpoint &endpoint) {
    std::size_t colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0 ||
        text.find(':') != colon || colon + 1 == text.size())
        return false;
    Endpoint parsed;
    parsed.ip = text.substr(0, colon);
    sockaddr_in address{};
    if (inet_pton(AF_INET, parsed.ip.c_str(), &address.sin_addr) != 1)
        return false;
    u64 port = 0;
    if (!parseUnsignedDecimal(text.substr(colon + 1), port) ||
        port == 0 || port > 65535)
        return false;
    parsed.port = static_cast<int>(port);
    endpoint = std::move(parsed);
    return true;
}

inline u64 hostToNet64(u64 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (static_cast<u64>(htonl(static_cast<u32>(value))) << 32U) |
           htonl(static_cast<u32>(value >> 32U));
#else
    return value;
#endif
}

inline u64 netToHost64(u64 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (static_cast<u64>(ntohl(static_cast<u32>(value))) << 32U) |
           ntohl(static_cast<u32>(value >> 32U));
#else
    return value;
#endif
}

inline bool readExact(int fd, void *buffer, std::size_t length) {
    char *cursor = static_cast<char *>(buffer);
    while (length != 0) {
        ssize_t count = recv(fd, cursor, length, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) return false;
        cursor += count;
        length -= static_cast<std::size_t>(count);
    }
    return true;
}

inline bool writeExact(int fd, const void *buffer, std::size_t length) {
    const char *cursor = static_cast<const char *>(buffer);
    while (length != 0) {
#ifdef MSG_NOSIGNAL
        ssize_t count = send(fd, cursor, length, MSG_NOSIGNAL);
#else
        ssize_t count = send(fd, cursor, length, 0);
#endif
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) return false;
        cursor += count;
        length -= static_cast<std::size_t>(count);
    }
    return true;
}

inline bool sendFrame(int fd, const std::string &payload) {
    if (payload.size() > MAX_FRAME) return false;
    u32 length = htonl(static_cast<u32>(payload.size()));
    return writeExact(fd, &length, sizeof(length)) &&
           (payload.empty() || writeExact(fd, payload.data(), payload.size()));
}

inline bool receiveFrame(int fd, std::string &payload) {
    u32 networkLength = 0;
    if (!readExact(fd, &networkLength, sizeof(networkLength))) return false;
    u32 length = ntohl(networkLength);
    if (length > MAX_FRAME) return false;
    payload.resize(length);
    return length == 0 || readExact(fd, &payload[0], length);
}

inline int connectTcp(const std::string &ip, int port, int timeoutSeconds = 5) {
    if (port <= 0 || port > 65535 || timeoutSeconds < 0) return -1;
    UniqueFd socketFd(socket(AF_INET, SOCK_STREAM, 0));
    if (!socketFd) return -1;

    int originalFlags = fcntl(socketFd.get(), F_GETFL, 0);
    if (originalFlags < 0 ||
        fcntl(socketFd.get(), F_SETFL, originalFlags | O_NONBLOCK) < 0)
        return -1;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) return -1;
    if (connect(socketFd.get(), reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) < 0) {
        if (errno != EINPROGRESS) return -1;
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(timeoutSeconds);
        for (;;) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (remaining.count() < 0) return -1;
            pollfd descriptor{socketFd.get(), POLLOUT, 0};
            int waitMilliseconds = static_cast<int>(std::min<long long>(
                remaining.count(), std::numeric_limits<int>::max()));
            int ready = poll(&descriptor, 1, waitMilliseconds);
            if (ready < 0 && errno == EINTR) continue;
            if (ready <= 0) return -1;
            int error = 0;
            socklen_t length = sizeof(error);
            if (getsockopt(socketFd.get(), SOL_SOCKET, SO_ERROR, &error,
                           &length) != 0 || error != 0) {
                if (error != 0) errno = error;
                return -1;
            }
            break;
        }
    }
    if (fcntl(socketFd.get(), F_SETFL, originalFlags) < 0) return -1;
    timeval timeout{};
    timeout.tv_sec = timeoutSeconds;
    setsockopt(socketFd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout,
               sizeof(timeout));
    setsockopt(socketFd.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout,
               sizeof(timeout));
    return socketFd.release();
}

inline int createListener(const std::string &ip, int port, int backlog = 64) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1 ||
        bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0 ||
        listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

inline std::string hexEncode(const std::string &value) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char byte : value) {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 15U]);
    }
    return result;
}

inline bool hexDecode(const std::string &value, std::string &result) {
    if (value.size() % 2 != 0) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    result.clear();
    result.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        int high = nibble(value[i]);
        int low = nibble(value[i + 1]);
        if (high < 0 || low < 0) return false;
        result.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

inline bool isHexInteger(const std::string &value,
                         std::size_t minimumLength = 1,
                         std::size_t maximumLength = static_cast<std::size_t>(-1)) {
    if (value.size() < minimumLength || value.size() > maximumLength) return false;
    for (char character : value) {
        bool digit = character >= '0' && character <= '9';
        bool lower = character >= 'a' && character <= 'f';
        bool upper = character >= 'A' && character <= 'F';
        if (!digit && !lower && !upper) return false;
    }
    return true;
}

inline bool isSha1Hex(const std::string &value) {
    return isHexInteger(value, 40, 40);
}

inline bool pieceCountForSize(u64 size, std::size_t &count) {
    u64 pieces = size / PIECE_SIZE + (size % PIECE_SIZE != 0 ? 1U : 0U);
    if (pieces > static_cast<u64>(std::numeric_limits<std::size_t>::max()))
        return false;
    count = static_cast<std::size_t>(pieces);
    return true;
}

inline std::vector<std::string> split(const std::string &text, char delimiter) {
    std::vector<std::string> parts;
    std::size_t begin = 0;
    while (true) {
        std::size_t end = text.find(delimiter, begin);
        parts.push_back(text.substr(begin, end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return parts;
}

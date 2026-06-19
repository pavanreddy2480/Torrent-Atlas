#pragma once

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using u32 = std::uint32_t;
using u64 = std::uint64_t;

static const std::size_t MAX_FRAME = 16U * 1024U * 1024U;
static const std::size_t PIECE_SIZE = 512U * 1024U;

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
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    timeval timeout{};
    timeout.tv_sec = timeoutSeconds;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1 ||
        connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
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

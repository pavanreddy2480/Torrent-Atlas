#include "common/encoding.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>

std::string toHex(const std::string &bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        hex.push_back(digits[byte >> 4U]);
        hex.push_back(digits[byte & 15U]);
    }
    return hex;
}

bool fromHex(const std::string &hex, std::string &bytes) {
    if (hex.size() % 2 != 0) return false;
    std::string decoded;
    decoded.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const char *begin = hex.data() + i;
        if (!std::isxdigit(static_cast<unsigned char>(begin[0])) ||
            !std::isxdigit(static_cast<unsigned char>(begin[1])))
            return false;
        unsigned value = 0;
        std::from_chars(begin, begin + 2, value, 16);
        decoded.push_back(static_cast<char>(value));
    }
    bytes = std::move(decoded);
    return true;
}

bool isHex(const std::string &text, std::size_t length) {
    return text.size() == length && std::all_of(text.begin(), text.end(), [](char c) {
               return std::isxdigit(static_cast<unsigned char>(c)) != 0;
           });
}

bool parseU64(const std::string &text, u64 &value) {
    const char *end = text.data() + text.size();
    u64 parsed = 0;
    auto [stop, error] = std::from_chars(text.data(), end, parsed);
    if (text.empty() || error != std::errc() || stop != end) return false;
    value = parsed;
    return true;
}

std::vector<std::string> split(const std::string &text, char delimiter) {
    std::vector<std::string> parts;
    std::size_t begin = 0;
    for (;;) {
        std::size_t end = text.find(delimiter, begin);
        parts.push_back(text.substr(begin, end - begin));
        if (end == std::string::npos) return parts;
        begin = end + 1;
    }
}

std::string join(const std::vector<std::string> &parts, char delimiter) {
    std::string joined;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) joined.push_back(delimiter);
        joined += parts[i];
    }
    return joined;
}

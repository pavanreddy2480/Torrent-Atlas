#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

class Sha1 {
    std::uint32_t state_[5] = {
        0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U
    };
    std::uint64_t bytes_ = 0;
    unsigned char buffer_[64]{};
    std::size_t buffered_ = 0;

    static std::uint32_t rotateLeft(std::uint32_t value, unsigned amount) {
        return (value << amount) | (value >> (32U - amount));
    }

    void transform(const unsigned char block[64]) {
        std::uint32_t words[80];
        for (int i = 0; i < 16; ++i) {
            words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24U) |
                       (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U) |
                       (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U) |
                       static_cast<std::uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 80; ++i)
            words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);

        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t function, constant;
            if (i < 20) {
                function = (b & c) | ((~b) & d);
                constant = 0x5a827999U;
            } else if (i < 40) {
                function = b ^ c ^ d;
                constant = 0x6ed9eba1U;
            } else if (i < 60) {
                function = (b & c) | (b & d) | (c & d);
                constant = 0x8f1bbcdcU;
            } else {
                function = b ^ c ^ d;
                constant = 0xca62c1d6U;
            }
            std::uint32_t temporary = rotateLeft(a, 5) + function + e + constant + words[i];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temporary;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
    }

public:
    void update(const void *data, std::size_t length) {
        const unsigned char *cursor = static_cast<const unsigned char *>(data);
        bytes_ += length;
        while (length != 0) {
            std::size_t amount = std::min(length, sizeof(buffer_) - buffered_);
            std::memcpy(buffer_ + buffered_, cursor, amount);
            buffered_ += amount;
            cursor += amount;
            length -= amount;
            if (buffered_ == sizeof(buffer_)) {
                transform(buffer_);
                buffered_ = 0;
            }
        }
    }

    std::string finalHex() {
        std::uint64_t bitCount = bytes_ * 8U;
        unsigned char padding[72]{0x80};
        std::size_t paddingLength = buffered_ < 56 ? 56 - buffered_ : 120 - buffered_;
        update(padding, paddingLength);
        unsigned char lengthBytes[8];
        for (int i = 0; i < 8; ++i)
            lengthBytes[7 - i] = static_cast<unsigned char>(bitCount >> (i * 8U));
        update(lengthBytes, sizeof(lengthBytes));

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (std::uint32_t value : state_) output << std::setw(8) << value;
        return output.str();
    }
};

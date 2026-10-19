#pragma once

// Timestamps in handshakes and peer requests must be within five minutes of
// now. Generous on purpose: replay safety comes from fresh keys and nonces;
// the timestamp only bounds how long a captured request stays usable.

#include "encoding.hpp"

#include <ctime>

inline long long unixSeconds() { return static_cast<long long>(std::time(nullptr)); }

inline bool isFreshTimestamp(const std::string &text) {
    constexpr long long WINDOW_SECONDS = 300;
    u64 value = 0;
    if (!parseU64(text, value) || value > static_cast<u64>(unixSeconds() + WINDOW_SECONDS))
        return false;
    return unixSeconds() - static_cast<long long>(value) <= WINDOW_SECONDS;
}

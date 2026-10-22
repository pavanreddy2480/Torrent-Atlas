#pragma once

/// @file freshness.hpp
/// Clock helpers for timestamps in handshakes and peer requests.
///
/// A timestamp is "fresh" if it is within five minutes of now, either way.
/// The window is generous on purpose: replay safety comes from fresh keys
/// and nonces; the timestamp only bounds how long a captured request stays
/// usable, and tolerates moderate clock skew between machines.

#include "common/encoding.hpp"

#include <ctime>

/// @return The current time as whole seconds since the Unix epoch.
inline long long unixSeconds() { return static_cast<long long>(std::time(nullptr)); }

/// Checks a decimal Unix timestamp against the current clock.
/// @param text Decimal seconds since the epoch, e.g. "1761140000".
/// @return true if text parses and lies within 300 s of now (past or future).
inline bool isFreshTimestamp(const std::string &text) {
    constexpr long long WINDOW_SECONDS = 300;
    u64 value = 0;
    if (!parseU64(text, value) || value > static_cast<u64>(unixSeconds() + WINDOW_SECONDS))
        return false;
    return unixSeconds() - static_cast<long long>(value) <= WINDOW_SECONDS;
}

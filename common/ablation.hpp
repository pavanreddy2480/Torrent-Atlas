#pragma once

/// @file ablation.hpp
/// Experiment switches for the ablation studies (see docs/ablations/).
/// Every switch is an environment variable; with none set the program
/// behaves exactly as the shipped design. Read once at startup.
///
///   TORRENT_ABL_ENCRYPT=0        peer transfers are not encrypted
///   TORRENT_ABL_ENCODING=base64  peer frames use base64 instead of hex
///   TORRENT_ABL_PIECE_VERIFY=0   skip the per-piece SHA-1 check on download
///   TORRENT_ABL_FINAL_VERIFY=0   skip the whole-file SHA-1 check
///   TORRENT_ABL_THREADS=N        N download threads (not capped by seeders)
///   TORRENT_ABL_PIECE_SIZE=N     piece size in bytes (all processes!)
///   TORRENT_ABL_SELECTION=...    rarest (default), sequential or random
///   TORRENT_ABL_DELAY_MS=N       seeder waits N ms before each reply (WAN)

#include <cstdlib>
#include <string>

namespace ablation {

/// @return The variable's text, or fallback if it is unset.
inline std::string text(const char *name, const std::string &fallback) {
    const char *value = std::getenv(name);
    return value ? value : fallback;
}

/// @return The variable as a number, or fallback if unset or not a number.
inline long number(const char *name, long fallback) {
    const char *value = std::getenv(name);
    char *end = nullptr;
    long parsed = value ? std::strtol(value, &end, 10) : 0;
    return value && end != value ? parsed : fallback;
}

inline bool encrypt() { static const bool v = number("TORRENT_ABL_ENCRYPT", 1) != 0; return v; }
inline bool base64() { static const bool v = text("TORRENT_ABL_ENCODING", "hex") == "base64"; return v; }
inline bool pieceVerify() { static const bool v = number("TORRENT_ABL_PIECE_VERIFY", 1) != 0; return v; }
inline bool finalVerify() { static const bool v = number("TORRENT_ABL_FINAL_VERIFY", 1) != 0; return v; }
inline long threads() { static const long v = number("TORRENT_ABL_THREADS", 0); return v; }
inline long pieceSize() { static const long v = number("TORRENT_ABL_PIECE_SIZE", 512 * 1024); return v; }
inline std::string selection() { static const std::string v = text("TORRENT_ABL_SELECTION", "rarest"); return v; }
inline long delayMs() { static const long v = number("TORRENT_ABL_DELAY_MS", 0); return v; }

}  // namespace ablation

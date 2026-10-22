#pragma once

/// @file encoding.hpp
/// Small text helpers shared by every program: hex encoding, strict decimal
/// parsing, and splitting/joining on a single-character delimiter.
///
/// All functions are pure (no global state) and safe to call from any thread.

#include <cstdint>
#include <string>
#include <vector>

/// Unsigned 64-bit integer used for sizes, session IDs and counters.
using u64 = std::uint64_t;

/// Encodes raw bytes as lowercase hex.
/// @param bytes Any bytes, including NUL; may be empty.
/// @return A string of exactly 2 * bytes.size() characters from [0-9a-f].
std::string toHex(const std::string &bytes);

/// Decodes hex text (upper or lower case) into raw bytes.
/// @param hex   Text to decode; must have an even length and only hex digits.
/// @param bytes Receives the decoded bytes. Left untouched on failure.
/// @return true on success; false for an odd length or any non-hex character.
bool fromHex(const std::string &hex, std::string &bytes);

/// Checks that text is exactly `length` hex digits.
/// @return true if text.size() == length and every character is a hex digit.
bool isHex(const std::string &text, std::size_t length);

/// Checks that text looks like a SHA-1 digest: exactly 40 hex digits.
inline bool isSha1Hex(const std::string &text) { return isHex(text, 40); }

/// Parses a strictly decimal unsigned 64-bit number.
/// Rejects empty text, signs, spaces, any trailing characters and overflow.
/// @param text  The digits to parse, e.g. "8080".
/// @param value Receives the number. Left untouched on failure.
/// @return true if the whole of text was a valid number.
bool parseU64(const std::string &text, u64 &value);

/// Splits text on every occurrence of delimiter.
/// Empty fields are kept: split("a||b", '|') gives {"a", "", "b"}, and
/// split("", '|') gives {""}. The result is never empty.
std::vector<std::string> split(const std::string &text, char delimiter);

/// Joins parts with delimiter between each pair; the inverse of split().
/// @return "" for an empty vector.
std::string join(const std::vector<std::string> &parts, char delimiter);

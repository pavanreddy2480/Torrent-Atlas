#pragma once

// Small text helpers shared by every program: hex, decimal numbers, and
// splitting/joining on a delimiter.

#include <cstdint>
#include <string>
#include <vector>

using u64 = std::uint64_t;

std::string toHex(const std::string &bytes);
bool fromHex(const std::string &hex, std::string &bytes);

// True when text is exactly `length` hex digits.
bool isHex(const std::string &text, std::size_t length);
inline bool isSha1Hex(const std::string &text) { return isHex(text, 40); }

// Decimal digits only: no sign, no spaces, no overflow.
bool parseU64(const std::string &text, u64 &value);

std::vector<std::string> split(const std::string &text, char delimiter);
std::string join(const std::vector<std::string> &parts, char delimiter);

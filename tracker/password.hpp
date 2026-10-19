#pragma once

// Stored passwords: "pbkdf2-sha256$<iterations>$<salt hex>$<digest hex>".

#include <string>

namespace password {

// salt must be 16 bytes. Returns an empty string on failure.
std::string hash(const std::string &password, const std::string &salt);
bool verify(const std::string &password, const std::string &stored);

}  // namespace password

#pragma once

/// @file password.hpp
/// Password hashing for stored accounts.
///
/// Stored form: "pbkdf2-sha256$<iterations>$<salt hex>$<digest hex>", with a
/// random 16-byte salt per user, 20 000 iterations and a 32-byte digest.
/// Only this string is ever kept or saved; the password itself never is.

#include <string>

namespace password {

/// Hashes a password for storage.
/// @param password The password as typed. Not modified; the caller erases it.
/// @param salt     16 random bytes, unique to this user.
/// @return The stored form, or "" if the salt is the wrong size or hashing
///         failed.
std::string hash(const std::string &password, const std::string &salt);

/// Checks a password against a stored hash. Recomputes the digest with the
/// stored salt and iteration count and compares in constant time.
/// @param stored A string produced by hash().
/// @return true only if stored is well formed and the password matches.
bool verify(const std::string &password, const std::string &stored);

}  // namespace password

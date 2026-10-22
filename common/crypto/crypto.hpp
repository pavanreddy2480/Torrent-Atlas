#pragma once

/// @file crypto.hpp
/// Thin wrappers over OpenSSL 3 for every cryptographic operation the
/// project uses. Nothing here implements cryptography itself.
///
/// Conventions:
///  - Keys, digests, nonces and signatures are raw bytes in std::string.
///  - Functions that produce bytes return an empty string on failure.
///  - Functions that check something return bool and never throw.
///  - Every function is safe to call from several threads at once.

#include <optional>
#include <string>

struct evp_md_ctx_st;

namespace crypto {

/// Cryptographically secure random bytes (OpenSSL RAND_bytes).
/// @return `length` bytes, or "" if the generator failed.
std::string randomBytes(std::size_t length);

/// Overwrites a secret with zeros in a way the compiler can't optimize away
/// (OPENSSL_cleanse), then clears it. Use on passwords and private keys.
void secureErase(std::string &secret);

/// Compares two byte strings in time that depends only on their length,
/// so an attacker can't learn how many leading bytes matched.
/// @return true if both have the same length and the same bytes.
bool constantTimeEqual(const std::string &left, const std::string &right);

/// SHA-256 of data.
/// @return The 32-byte digest, or "" on failure.
std::string sha256(const std::string &data);

/// HMAC-SHA256 of data under key.
/// @param key Any length; 32 random bytes is typical.
/// @return The 32-byte MAC, or "" on failure.
std::string hmacSha256(const std::string &key, const std::string &data);

/// PBKDF2-HMAC-SHA256 key derivation, used for password hashing.
/// @param iterations Work factor; 1..INT_MAX.
/// @param length     Bytes of output wanted; 1..INT_MAX.
/// @return `length` derived bytes, or "" for invalid arguments or failure.
std::string pbkdf2Sha256(const std::string &password, const std::string &salt,
                         unsigned iterations, std::size_t length);

/// Streaming SHA-1, for piece and whole-file hashes that are too large to
/// hold in memory at once. Feed data with update() in any number of chunks,
/// then call hexDigest() once. Not copyable; not thread-safe.
class Sha1 {
public:
    Sha1();
    ~Sha1();
    Sha1(const Sha1 &) = delete;
    Sha1 &operator=(const Sha1 &) = delete;

    /// Adds `length` bytes at data to the running hash.
    void update(const void *data, std::size_t length);

    /// Finishes the hash.
    /// @return 40 lowercase hex digits. Call at most once.
    std::string hexDigest();

private:
    evp_md_ctx_st *context_;   ///< Owned OpenSSL digest context.
};

/// SHA-1 of data in one call.
/// @return 40 lowercase hex digits.
std::string sha1Hex(const std::string &data);

/// One AES-256-GCM message: a 12-byte nonce, the ciphertext (same length as
/// the plaintext) and a 16-byte authentication tag.
struct AesGcmMessage {
    std::string nonce;
    std::string ciphertext;
    std::string tag;
};

/// Encrypts and authenticates plain under a fresh random nonce.
/// @param key  32 bytes.
/// @param aad  Additional data that is authenticated but not encrypted; the
///             same aad must be given to decrypt().
/// @param message Receives nonce, ciphertext and tag.
/// @return false if the key is the wrong size or OpenSSL fails.
bool encrypt(const std::string &key, const std::string &aad, const std::string &plain,
             AesGcmMessage &message);

/// Checks the tag and decrypts.
/// @param plain Receives the plaintext; left untouched on failure.
/// @return false if anything was tampered with (nonce, ciphertext, tag or
///         aad), the key is wrong, or the sizes are invalid.
bool decrypt(const std::string &key, const std::string &aad, const AesGcmMessage &message,
             std::string &plain);

/// A raw 32-byte private key and its 32-byte public key.
struct KeyPair {
    std::string privateKey;
    std::string publicKey;
};

/// Generates an Ed25519 signing key pair (the tracker's long-term identity).
/// @return The pair, or std::nullopt on failure.
std::optional<KeyPair> ed25519KeyPair();

/// Signs message with a raw 32-byte Ed25519 private key.
/// @return The 64-byte signature, or "" if the key is invalid.
std::string ed25519Sign(const std::string &privateKey, const std::string &message);

/// Verifies an Ed25519 signature.
/// @return true only if signature is a valid signature of message by the
///         holder of the private key matching publicKey.
bool ed25519Verify(const std::string &publicKey, const std::string &message,
                   const std::string &signature);

/// Generates an X25519 key-agreement pair (fresh for every connection).
/// @return The pair, or std::nullopt on failure.
std::optional<KeyPair> x25519KeyPair();

/// Computes the X25519 shared secret between our private key and the
/// other side's public key. Both sides get the same 32 bytes.
/// @return 32 bytes, or "" if either key is invalid.
std::string x25519SharedSecret(const std::string &privateKey, const std::string &peerPublicKey);

}  // namespace crypto

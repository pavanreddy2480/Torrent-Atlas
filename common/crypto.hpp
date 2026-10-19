#pragma once

// Thin wrappers over OpenSSL. Keys and digests are raw bytes in std::string.

#include <optional>
#include <string>

struct evp_md_ctx_st;

namespace crypto {

std::string randomBytes(std::size_t length);   // empty on failure
void secureErase(std::string &secret);
bool constantTimeEqual(const std::string &left, const std::string &right);

std::string sha256(const std::string &data);
std::string pbkdf2Sha256(const std::string &password, const std::string &salt,
                         unsigned iterations, std::size_t length);

// Streaming SHA-1, used for piece and file hashes (lowercase hex).
class Sha1 {
public:
    Sha1();
    ~Sha1();
    Sha1(const Sha1 &) = delete;
    Sha1 &operator=(const Sha1 &) = delete;
    void update(const void *data, std::size_t length);
    std::string hexDigest();

private:
    evp_md_ctx_st *context_;
};

std::string sha1Hex(const std::string &data);

// AES-256-GCM with a fresh random 12-byte nonce and a 16-byte tag.
struct AesGcmMessage {
    std::string nonce;
    std::string ciphertext;
    std::string tag;
};
bool encrypt(const std::string &key, const std::string &aad, const std::string &plain,
             AesGcmMessage &message);
bool decrypt(const std::string &key, const std::string &aad, const AesGcmMessage &message,
             std::string &plain);

// Raw 32-byte keys.
struct KeyPair {
    std::string privateKey;
    std::string publicKey;
};

// Ed25519 signatures: the tracker cluster's long-term identity.
std::optional<KeyPair> ed25519KeyPair();
std::string ed25519Sign(const std::string &privateKey, const std::string &message);
bool ed25519Verify(const std::string &publicKey, const std::string &message,
                   const std::string &signature);

// X25519 key agreement: fresh keys for every connection.
std::optional<KeyPair> x25519KeyPair();
std::string x25519SharedSecret(const std::string &privateKey, const std::string &peerPublicKey);

}  // namespace crypto

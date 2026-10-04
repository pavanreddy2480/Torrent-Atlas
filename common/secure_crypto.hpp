#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <string>

namespace secure_crypto_detail {

struct CipherContextDeleter {
    void operator()(EVP_CIPHER_CTX *context) const {
        EVP_CIPHER_CTX_free(context);
    }
};

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter>;

struct PkeyDeleter {
    void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
};
struct PkeyContextDeleter {
    void operator()(EVP_PKEY_CTX *context) const { EVP_PKEY_CTX_free(context); }
};
struct MdContextDeleter {
    void operator()(EVP_MD_CTX *context) const { EVP_MD_CTX_free(context); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;
using MdContext = std::unique_ptr<EVP_MD_CTX, MdContextDeleter>;

inline const unsigned char *bytes(const std::string &value) {
    return reinterpret_cast<const unsigned char *>(value.data());
}

// Generates a raw 32-byte private/public key pair for X25519 or Ed25519.
inline bool generateRawKeyPair(int type, std::string &privateKey,
                               std::string &publicKey) {
    PkeyContext context(EVP_PKEY_CTX_new_id(type, nullptr));
    EVP_PKEY *raw = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_keygen(context.get(), &raw) != 1)
        return false;
    Pkey key(raw);
    std::size_t privateLength = 32, publicLength = 32;
    privateKey.assign(32, '\0');
    publicKey.assign(32, '\0');
    return EVP_PKEY_get_raw_private_key(
               key.get(), reinterpret_cast<unsigned char *>(privateKey.data()),
               &privateLength) == 1 &&
           EVP_PKEY_get_raw_public_key(
               key.get(), reinterpret_cast<unsigned char *>(publicKey.data()),
               &publicLength) == 1 &&
           privateLength == 32 && publicLength == 32;
}

inline bool validIntLength(std::size_t length) {
    return length <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

}  // namespace secure_crypto_detail

struct AesGcmMessage {
    std::string nonce;
    std::string ciphertext;
    std::string tag;
};

inline bool secureRandom(void *buffer, std::size_t length) {
    if (!secure_crypto_detail::validIntLength(length)) return false;
    return length == 0 ||
           RAND_bytes(static_cast<unsigned char *>(buffer),
                      static_cast<int>(length)) == 1;
}

inline std::string randomBytes(std::size_t length) {
    std::string result(length, '\0');
    if (length != 0 && !secureRandom(result.data(), length)) result.clear();
    return result;
}

inline std::string pbkdf2HmacSha256(const std::string &password,
                                    const std::string &salt,
                                    std::uint32_t iterations,
                                    std::size_t outputLength) {
    if (iterations == 0 || outputLength == 0 ||
        !secure_crypto_detail::validIntLength(password.size()) ||
        !secure_crypto_detail::validIntLength(salt.size()) ||
        !secure_crypto_detail::validIntLength(outputLength) ||
        iterations > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
        return {};
    std::string output(outputLength, '\0');
    if (PKCS5_PBKDF2_HMAC(
            password.data(), static_cast<int>(password.size()),
            reinterpret_cast<const unsigned char *>(salt.data()),
            static_cast<int>(salt.size()), static_cast<int>(iterations),
            EVP_sha256(), static_cast<int>(outputLength),
            reinterpret_cast<unsigned char *>(output.data())) != 1)
        return {};
    return output;
}

inline bool constantTimeEqual(const std::string &left,
                              const std::string &right) {
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

inline void secureErase(std::string &value) {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}

inline bool aes256GcmEncrypt(const std::string &key, const std::string &aad,
                             const std::string &plain,
                             AesGcmMessage &message) {
    constexpr std::size_t NONCE_SIZE = 12;
    constexpr std::size_t TAG_SIZE = 16;
    if (key.size() != 32 ||
        !secure_crypto_detail::validIntLength(aad.size()) ||
        !secure_crypto_detail::validIntLength(plain.size()))
        return false;
    message.nonce = randomBytes(NONCE_SIZE);
    message.ciphertext.assign(plain.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    message.tag.assign(TAG_SIZE, '\0');
    if (message.nonce.size() != NONCE_SIZE) return false;
    secure_crypto_detail::CipherContext context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_EncryptInit_ex(
            context.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(key.data()),
            reinterpret_cast<const unsigned char *>(message.nonce.data())) != 1)
        return false;
    int length = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(
            context.get(), nullptr, &length,
            reinterpret_cast<const unsigned char *>(aad.data()),
            static_cast<int>(aad.size())) != 1)
        return false;
    length = 0;
    if (!plain.empty() &&
        EVP_EncryptUpdate(
            context.get(),
            reinterpret_cast<unsigned char *>(message.ciphertext.data()),
            &length,
            reinterpret_cast<const unsigned char *>(plain.data()),
            static_cast<int>(plain.size())) != 1)
        return false;
    int total = length;
    if (EVP_EncryptFinal_ex(
            context.get(),
            reinterpret_cast<unsigned char *>(message.ciphertext.data()) + total,
            &length) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(message.tag.size()),
                            message.tag.data()) != 1)
        return false;
    message.ciphertext.resize(static_cast<std::size_t>(total + length));
    return true;
}

inline bool aes256GcmDecrypt(const std::string &key, const std::string &aad,
                             const AesGcmMessage &message,
                             std::string &plain) {
    if (key.size() != 32 || message.nonce.size() != 12 ||
        message.tag.size() != 16 ||
        !secure_crypto_detail::validIntLength(aad.size()) ||
        !secure_crypto_detail::validIntLength(message.ciphertext.size()))
        return false;
    secure_crypto_detail::CipherContext context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_DecryptInit_ex(
            context.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(key.data()),
            reinterpret_cast<const unsigned char *>(message.nonce.data())) != 1)
        return false;
    std::string output(message.ciphertext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    int length = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(
            context.get(), nullptr, &length,
            reinterpret_cast<const unsigned char *>(aad.data()),
            static_cast<int>(aad.size())) != 1)
        return false;
    length = 0;
    if (!message.ciphertext.empty() &&
        EVP_DecryptUpdate(
            context.get(), reinterpret_cast<unsigned char *>(output.data()),
            &length,
            reinterpret_cast<const unsigned char *>(message.ciphertext.data()),
            static_cast<int>(message.ciphertext.size())) != 1)
        return false;
    int total = length;
    if (EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(message.tag.size()),
            const_cast<char *>(message.tag.data())) != 1 ||
        EVP_DecryptFinal_ex(
            context.get(), reinterpret_cast<unsigned char *>(output.data()) + total,
            &length) != 1)
        return false;
    output.resize(static_cast<std::size_t>(total + length));
    plain = std::move(output);
    return true;
}

inline std::string sha256(const std::string &data) {
    std::string digest(32, '\0');
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(),
                   reinterpret_cast<unsigned char *>(digest.data()), &length,
                   EVP_sha256(), nullptr) != 1 || length != 32)
        return {};
    return digest;
}

inline std::string hmacSha256(const std::string &key, const std::string &data) {
    std::string mac(32, '\0');
    unsigned int length = 0;
    if (!secure_crypto_detail::validIntLength(key.size()) ||
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             secure_crypto_detail::bytes(data), data.size(),
             reinterpret_cast<unsigned char *>(mac.data()), &length) == nullptr ||
        length != 32)
        return {};
    return mac;
}

// Ed25519 signatures: the load balancer's long-term identity.
inline bool ed25519KeyPair(std::string &privateKey, std::string &publicKey) {
    return secure_crypto_detail::generateRawKeyPair(EVP_PKEY_ED25519, privateKey, publicKey);
}

inline std::string ed25519Sign(const std::string &privateKey, const std::string &message) {
    using namespace secure_crypto_detail;
    if (privateKey.size() != 32) return {};
    Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                          bytes(privateKey), privateKey.size()));
    MdContext context(EVP_MD_CTX_new());
    std::string signature(64, '\0');
    std::size_t length = signature.size();
    if (!key || !context ||
        EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestSign(context.get(), reinterpret_cast<unsigned char *>(signature.data()),
                       &length, bytes(message), message.size()) != 1 ||
        length != 64)
        return {};
    return signature;
}

inline bool ed25519Verify(const std::string &publicKey, const std::string &message,
                          const std::string &signature) {
    using namespace secure_crypto_detail;
    if (publicKey.size() != 32 || signature.size() != 64) return false;
    Pkey key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                         bytes(publicKey), publicKey.size()));
    MdContext context(EVP_MD_CTX_new());
    return key && context &&
           EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
           EVP_DigestVerify(context.get(), bytes(signature), signature.size(),
                            bytes(message), message.size()) == 1;
}

// X25519 key agreement: fresh keys per connection.
inline bool x25519KeyPair(std::string &privateKey, std::string &publicKey) {
    return secure_crypto_detail::generateRawKeyPair(EVP_PKEY_X25519, privateKey, publicKey);
}

inline std::string x25519SharedSecret(const std::string &privateKey,
                                      const std::string &peerPublicKey) {
    using namespace secure_crypto_detail;
    if (privateKey.size() != 32 || peerPublicKey.size() != 32) return {};
    Pkey own(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                          bytes(privateKey), privateKey.size()));
    Pkey peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                          bytes(peerPublicKey), peerPublicKey.size()));
    if (!own || !peer) return {};
    PkeyContext context(EVP_PKEY_CTX_new(own.get(), nullptr));
    std::string secret(32, '\0');
    std::size_t length = secret.size();
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(context.get(), reinterpret_cast<unsigned char *>(secret.data()),
                        &length) != 1 ||
        length != 32)
        return {};
    return secret;
}

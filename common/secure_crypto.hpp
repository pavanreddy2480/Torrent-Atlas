#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
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

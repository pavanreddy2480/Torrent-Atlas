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

inline bool validIntLength(std::size_t length) {
    return length <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

}  // namespace secure_crypto_detail

inline std::string sha256(const std::string &data) {
    std::string digest(EVP_MAX_MD_SIZE, '\0');
    unsigned int length = 0;
    if (!EVP_Digest(data.data(), data.size(),
                    reinterpret_cast<unsigned char *>(digest.data()), &length,
                    EVP_sha256(), nullptr))
        return {};
    digest.resize(length);
    return digest;
}

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

inline std::string hmacSha256(const std::string &key,
                              const std::string &message) {
    std::string digest(EVP_MAX_MD_SIZE, '\0');
    unsigned int length = 0;
    if (!secure_crypto_detail::validIntLength(key.size()) ||
        !HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char *>(message.data()),
              message.size(),
              reinterpret_cast<unsigned char *>(digest.data()), &length))
        return {};
    digest.resize(length);
    return digest;
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

inline std::string aes256CbcEncrypt(const std::string &key,
                                    const std::string &iv,
                                    const std::string &plain) {
    if (key.size() != 32 || iv.size() != 16 ||
        !secure_crypto_detail::validIntLength(plain.size()))
        return {};
    secure_crypto_detail::CipherContext context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_EncryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key.data()),
                           reinterpret_cast<const unsigned char *>(iv.data())) != 1)
        return {};
    std::string cipher(plain.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    int first = 0;
    int final = 0;
    if (EVP_EncryptUpdate(
            context.get(),
            reinterpret_cast<unsigned char *>(cipher.data()), &first,
            reinterpret_cast<const unsigned char *>(plain.data()),
            static_cast<int>(plain.size())) != 1 ||
        EVP_EncryptFinal_ex(
            context.get(),
            reinterpret_cast<unsigned char *>(cipher.data()) + first,
            &final) != 1)
        return {};
    cipher.resize(static_cast<std::size_t>(first + final));
    return cipher;
}

inline bool aes256CbcDecrypt(const std::string &key,
                             const std::string &iv,
                             const std::string &cipher,
                             std::string &plain) {
    if (key.size() != 32 || iv.size() != 16 || cipher.empty() ||
        !secure_crypto_detail::validIntLength(cipher.size()))
        return false;
    secure_crypto_detail::CipherContext context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key.data()),
                           reinterpret_cast<const unsigned char *>(iv.data())) != 1)
        return false;
    std::string output(cipher.size(), '\0');
    int first = 0;
    int final = 0;
    if (EVP_DecryptUpdate(
            context.get(),
            reinterpret_cast<unsigned char *>(output.data()), &first,
            reinterpret_cast<const unsigned char *>(cipher.data()),
            static_cast<int>(cipher.size())) != 1 ||
        EVP_DecryptFinal_ex(
            context.get(),
            reinterpret_cast<unsigned char *>(output.data()) + first,
            &final) != 1)
        return false;
    output.resize(static_cast<std::size_t>(first + final));
    plain = std::move(output);
    return true;
}

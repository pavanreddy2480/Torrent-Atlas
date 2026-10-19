#include "crypto.hpp"

#include "encoding.hpp"
#include "openssl_ptr.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <climits>

namespace crypto {

namespace {

using Pkey = OpenSslPtr<EVP_PKEY, EVP_PKEY_free>;
using PkeyContext = OpenSslPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using MdContext = OpenSslPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using CipherContext = OpenSslPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;

const unsigned char *bytes(const std::string &value) {
    return reinterpret_cast<const unsigned char *>(value.data());
}

unsigned char *bytes(std::string &value) {
    return reinterpret_cast<unsigned char *>(value.data());
}

bool fitsInt(std::size_t length) { return length <= static_cast<std::size_t>(INT_MAX); }

std::optional<KeyPair> generateKeyPair(int type) {
    PkeyContext context(EVP_PKEY_CTX_new_id(type, nullptr));
    EVP_PKEY *raw = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_keygen(context.get(), &raw) != 1)
        return std::nullopt;
    Pkey key(raw);
    KeyPair pair{std::string(32, '\0'), std::string(32, '\0')};
    std::size_t privateLength = 32, publicLength = 32;
    if (EVP_PKEY_get_raw_private_key(key.get(), bytes(pair.privateKey), &privateLength) != 1 ||
        EVP_PKEY_get_raw_public_key(key.get(), bytes(pair.publicKey), &publicLength) != 1 ||
        privateLength != 32 || publicLength != 32)
        return std::nullopt;
    return pair;
}

}  // namespace

std::string randomBytes(std::size_t length) {
    std::string result(length, '\0');
    if (!fitsInt(length) || RAND_bytes(bytes(result), static_cast<int>(length)) != 1)
        result.clear();
    return result;
}

void secureErase(std::string &secret) {
    if (!secret.empty()) OPENSSL_cleanse(secret.data(), secret.size());
    secret.clear();
}

bool constantTimeEqual(const std::string &left, const std::string &right) {
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

std::string sha256(const std::string &data) {
    std::string digest(32, '\0');
    unsigned length = 0;
    if (EVP_Digest(data.data(), data.size(), bytes(digest), &length, EVP_sha256(), nullptr) != 1)
        return {};
    return digest;
}

std::string pbkdf2Sha256(const std::string &password, const std::string &salt,
                         unsigned iterations, std::size_t length) {
    std::string output(length, '\0');
    if (iterations == 0 || iterations > INT_MAX || length == 0 || !fitsInt(length) ||
        !fitsInt(password.size()) || !fitsInt(salt.size()) ||
        PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), bytes(salt),
                          static_cast<int>(salt.size()), static_cast<int>(iterations),
                          EVP_sha256(), static_cast<int>(length), bytes(output)) != 1)
        return {};
    return output;
}

Sha1::Sha1() : context_(EVP_MD_CTX_new()) { EVP_DigestInit_ex(context_, EVP_sha1(), nullptr); }

Sha1::~Sha1() { EVP_MD_CTX_free(context_); }

void Sha1::update(const void *data, std::size_t length) {
    EVP_DigestUpdate(context_, data, length);
}

std::string Sha1::hexDigest() {
    std::string digest(20, '\0');
    unsigned length = 0;
    EVP_DigestFinal_ex(context_, bytes(digest), &length);
    return toHex(digest);
}

std::string sha1Hex(const std::string &data) {
    Sha1 hash;
    hash.update(data.data(), data.size());
    return hash.hexDigest();
}

bool encrypt(const std::string &key, const std::string &aad, const std::string &plain,
             AesGcmMessage &message) {
    if (key.size() != 32 || !fitsInt(aad.size()) || !fitsInt(plain.size())) return false;
    message.nonce = randomBytes(NONCE_SIZE);
    message.ciphertext.assign(plain.size(), '\0');
    message.tag.assign(TAG_SIZE, '\0');
    CipherContext context(EVP_CIPHER_CTX_new());
    int length = 0;
    return message.nonce.size() == NONCE_SIZE && context &&
           EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, bytes(key),
                              bytes(message.nonce)) == 1 &&
           EVP_EncryptUpdate(context.get(), nullptr, &length, bytes(aad),
                             static_cast<int>(aad.size())) == 1 &&
           EVP_EncryptUpdate(context.get(), bytes(message.ciphertext), &length, bytes(plain),
                             static_cast<int>(plain.size())) == 1 &&
           EVP_EncryptFinal_ex(context.get(), nullptr, &length) == 1 &&
           EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                               message.tag.data()) == 1;
}

bool decrypt(const std::string &key, const std::string &aad, const AesGcmMessage &message,
             std::string &plain) {
    if (key.size() != 32 || message.nonce.size() != NONCE_SIZE ||
        message.tag.size() != TAG_SIZE || !fitsInt(aad.size()) ||
        !fitsInt(message.ciphertext.size()))
        return false;
    std::string output(message.ciphertext.size(), '\0');
    std::string tag = message.tag;
    CipherContext context(EVP_CIPHER_CTX_new());
    int length = 0;
    unsigned char unused[16];
    if (!context ||
        EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, bytes(key),
                           bytes(message.nonce)) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &length, bytes(aad),
                          static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), bytes(output), &length, bytes(message.ciphertext),
                          static_cast<int>(message.ciphertext.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1 ||
        EVP_DecryptFinal_ex(context.get(), unused, &length) != 1)
        return false;
    plain = std::move(output);
    return true;
}

std::optional<KeyPair> ed25519KeyPair() { return generateKeyPair(EVP_PKEY_ED25519); }

std::string ed25519Sign(const std::string &privateKey, const std::string &message) {
    if (privateKey.size() != 32) return {};
    Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, bytes(privateKey), 32));
    MdContext context(EVP_MD_CTX_new());
    std::string signature(64, '\0');
    std::size_t length = signature.size();
    if (!key || !context ||
        EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestSign(context.get(), bytes(signature), &length, bytes(message),
                       message.size()) != 1 ||
        length != 64)
        return {};
    return signature;
}

bool ed25519Verify(const std::string &publicKey, const std::string &message,
                   const std::string &signature) {
    if (publicKey.size() != 32 || signature.size() != 64) return false;
    Pkey key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes(publicKey), 32));
    MdContext context(EVP_MD_CTX_new());
    return key && context &&
           EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
           EVP_DigestVerify(context.get(), bytes(signature), signature.size(), bytes(message),
                            message.size()) == 1;
}

std::optional<KeyPair> x25519KeyPair() { return generateKeyPair(EVP_PKEY_X25519); }

std::string x25519SharedSecret(const std::string &privateKey, const std::string &peerPublicKey) {
    if (privateKey.size() != 32 || peerPublicKey.size() != 32) return {};
    Pkey own(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, bytes(privateKey), 32));
    Pkey peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, bytes(peerPublicKey), 32));
    if (!own || !peer) return {};
    PkeyContext context(EVP_PKEY_CTX_new(own.get(), nullptr));
    std::string secret(32, '\0');
    std::size_t length = secret.size();
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(context.get(), bytes(secret), &length) != 1 || length != 32)
        return {};
    return secret;
}

}  // namespace crypto

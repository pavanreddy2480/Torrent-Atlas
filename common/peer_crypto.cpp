#include "peer_crypto.hpp"

#include "protocol.hpp"
#include "secure_crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>

namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
};

struct PkeyContextDeleter {
    void operator()(EVP_PKEY_CTX *context) const {
        EVP_PKEY_CTX_free(context);
    }
};

struct MdContextDeleter {
    void operator()(EVP_MD_CTX *context) const { EVP_MD_CTX_free(context); }
};

struct CipherContextDeleter {
    void operator()(EVP_CIPHER_CTX *context) const {
        EVP_CIPHER_CTX_free(context);
    }
};

struct KdfDeleter {
    void operator()(EVP_KDF *kdf) const { EVP_KDF_free(kdf); }
};

struct KdfContextDeleter {
    void operator()(EVP_KDF_CTX *context) const {
        EVP_KDF_CTX_free(context);
    }
};

using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;
using MdContext = std::unique_ptr<EVP_MD_CTX, MdContextDeleter>;
using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter>;
using Kdf = std::unique_ptr<EVP_KDF, KdfDeleter>;
using KdfContext = std::unique_ptr<EVP_KDF_CTX, KdfContextDeleter>;

constexpr std::size_t kEd25519KeyBytes = 32;
constexpr std::size_t kEd25519SignatureBytes = 64;
constexpr std::size_t kX25519KeyBytes = 32;
constexpr std::size_t kAeadKeyBytes = 32;
constexpr std::size_t kAeadNonceBytes = 12;
constexpr std::size_t kAeadTagBytes = 16;

bool validIntLength(std::size_t size) {
    return size <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

Pkey generateKey(int keyType) {
    PkeyContext context(EVP_PKEY_CTX_new_id(keyType, nullptr));
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1) return {};
    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw) != 1) return {};
    return Pkey(raw);
}

std::string rawPrivateKey(EVP_PKEY *key) {
    std::string raw(kEd25519KeyBytes, '\0');
    std::size_t length = raw.size();
    if (EVP_PKEY_get_raw_private_key(
            key, reinterpret_cast<unsigned char *>(raw.data()), &length) != 1)
        return {};
    raw.resize(length);
    return raw;
}

std::string rawPublicKey(EVP_PKEY *key) {
    std::string raw(kEd25519KeyBytes, '\0');
    std::size_t length = raw.size();
    if (EVP_PKEY_get_raw_public_key(
            key, reinterpret_cast<unsigned char *>(raw.data()), &length) != 1)
        return {};
    raw.resize(length);
    return raw;
}

std::string identityPath(const std::string &identityName) {
    const char *configured = std::getenv("TORRENT_IDENTITY_DIR");
    const char *home = std::getenv("HOME");
    std::string directory;
    if (configured && *configured) {
        directory = configured;
    } else if (home && *home) {
        std::string root = std::string(home) + "/.torrent-dashboard";
        mkdir(root.c_str(), 0700);
        directory = root + "/identities";
    } else {
        directory = ".torrent-identities";
    }
    mkdir(directory.c_str(), 0700);
    chmod(directory.c_str(), 0700);
    return directory + "/" + hexEncode(sha256(identityName)) + ".ed25519";
}

bool writePrivateKey(const std::string &path, const std::string &privateKey) {
    int descriptor = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) return false;
    std::size_t written = 0;
    while (written < privateKey.size()) {
        ssize_t count = write(descriptor, privateKey.data() + written,
                              privateKey.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(descriptor);
            unlink(path.c_str());
            return false;
        }
        written += static_cast<std::size_t>(count);
    }
    bool ok = fsync(descriptor) == 0 && close(descriptor) == 0;
    if (!ok) unlink(path.c_str());
    return ok;
}

std::string readPrivateKey(const std::string &path) {
    struct stat info {};
    if (stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode) ||
        (info.st_mode & 077) != 0 || info.st_size != kEd25519KeyBytes)
        return {};
    std::ifstream input(path, std::ios::binary);
    std::string key(kEd25519KeyBytes, '\0');
    input.read(key.data(), static_cast<std::streamsize>(key.size()));
    return input && input.peek() == std::char_traits<char>::eof() ? key
                                                                  : std::string{};
}

}  // namespace

struct PeerIdentity::Impl {
    explicit Impl(Pkey identityKey) : identity(std::move(identityKey)) {}
    Pkey identity;
};

PeerIdentity::PeerIdentity(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

PeerIdentity::~PeerIdentity() = default;
PeerIdentity::PeerIdentity(PeerIdentity &&) noexcept = default;
PeerIdentity &PeerIdentity::operator=(PeerIdentity &&) noexcept = default;

std::unique_ptr<PeerIdentity> PeerIdentity::loadOrCreate(
    const std::string &identityName) {
    std::string path = identityPath(identityName);
    std::string privateKey = readPrivateKey(path);
    Pkey key;
    if (!privateKey.empty()) {
        key.reset(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(privateKey.data()),
            privateKey.size()));
    } else {
        key = generateKey(EVP_PKEY_ED25519);
        if (!key) return {};
        privateKey = rawPrivateKey(key.get());
        if (privateKey.size() != kEd25519KeyBytes) return {};
        if (!writePrivateKey(path, privateKey)) {
            privateKey = readPrivateKey(path);
            if (privateKey.size() != kEd25519KeyBytes) return {};
            key.reset(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED25519, nullptr,
                reinterpret_cast<const unsigned char *>(privateKey.data()),
                privateKey.size()));
        }
    }
    secureErase(privateKey);
    if (!key) return {};
    return std::unique_ptr<PeerIdentity>(
        new PeerIdentity(std::make_unique<Impl>(std::move(key))));
}

std::string PeerIdentity::publicHex() const {
    return hexEncode(rawPublicKey(impl_->identity.get()));
}

std::string PeerIdentity::signHex(const std::string &message) const {
    MdContext context(EVP_MD_CTX_new());
    if (!context ||
        EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr,
                           impl_->identity.get()) != 1)
        return {};
    std::string signature(kEd25519SignatureBytes, '\0');
    std::size_t length = signature.size();
    if (EVP_DigestSign(
            context.get(),
            reinterpret_cast<unsigned char *>(signature.data()), &length,
            reinterpret_cast<const unsigned char *>(message.data()),
            message.size()) != 1)
        return {};
    signature.resize(length);
    return hexEncode(signature);
}

bool PeerIdentity::verifyHex(const std::string &message,
                             const std::string &signatureHex,
                             const std::string &publicKeyHex) const {
    std::string signature;
    std::string publicKey;
    if (!hexDecode(signatureHex, signature) ||
        !hexDecode(publicKeyHex, publicKey) ||
        signature.size() != kEd25519SignatureBytes ||
        publicKey.size() != kEd25519KeyBytes)
        return false;
    Pkey key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(publicKey.data()),
        publicKey.size()));
    MdContext context(EVP_MD_CTX_new());
    return key && context &&
           EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr,
                                key.get()) == 1 &&
           EVP_DigestVerify(
               context.get(),
               reinterpret_cast<const unsigned char *>(signature.data()),
               signature.size(),
               reinterpret_cast<const unsigned char *>(message.data()),
               message.size()) == 1;
}

bool PeerIdentity::generateEphemeral(std::string &privateKey,
                                     std::string &publicKeyHex) const {
    Pkey key = generateKey(EVP_PKEY_X25519);
    if (!key) return false;
    privateKey = rawPrivateKey(key.get());
    std::string publicKey = rawPublicKey(key.get());
    if (privateKey.size() != kX25519KeyBytes ||
        publicKey.size() != kX25519KeyBytes) {
        secureErase(privateKey);
        return false;
    }
    publicKeyHex = hexEncode(publicKey);
    return true;
}

bool PeerIdentity::deriveEphemeralSecret(
    const std::string &privateKey, const std::string &peerPublicKeyHex,
    std::string &secret) const {
    std::string peerPublicKey;
    if (privateKey.size() != kX25519KeyBytes ||
        !hexDecode(peerPublicKeyHex, peerPublicKey) ||
        peerPublicKey.size() != kX25519KeyBytes)
        return false;
    Pkey local(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char *>(privateKey.data()),
        privateKey.size()));
    Pkey peer(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char *>(peerPublicKey.data()),
        peerPublicKey.size()));
    PkeyContext context(local ? EVP_PKEY_CTX_new(local.get(), nullptr)
                              : nullptr);
    std::size_t length = kX25519KeyBytes;
    secret.assign(length, '\0');
    if (!local || !peer || !context ||
        EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(
            context.get(),
            reinterpret_cast<unsigned char *>(secret.data()), &length) != 1) {
        secureErase(secret);
        return false;
    }
    secret.resize(length);
    return true;
}

std::string PeerIdentity::deriveSessionKey(
    const std::string &sharedSecret, const std::string &transcript) const {
    std::string salt = sha256(transcript);
    std::string info = "torrent-peer-v2";
    Kdf kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    KdfContext context(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr);
    if (!context) return {};
    char digest[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<char *>(sharedSecret.data()), sharedSecret.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, info.data(), info.size()),
        OSSL_PARAM_construct_end(),
    };
    std::string key(kAeadKeyBytes, '\0');
    if (EVP_KDF_derive(
            context.get(), reinterpret_cast<unsigned char *>(key.data()),
            key.size(), parameters) != 1)
        return {};
    return key;
}

bool PeerIdentity::encrypt(const std::string &key, const std::string &aad,
                           const std::string &plain,
                           PeerAeadMessage &message) const {
    if (key.size() != kAeadKeyBytes || !validIntLength(aad.size()) ||
        !validIntLength(plain.size()))
        return false;
    message.nonce = randomBytes(kAeadNonceBytes);
    message.tag.assign(kAeadTagBytes, '\0');
    if (message.nonce.size() != kAeadNonceBytes) return false;
    CipherContext context(EVP_CIPHER_CTX_new());
    int length = 0;
    int total = 0;
    message.ciphertext.assign(plain.size(), '\0');
    if (!context ||
        EVP_EncryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(message.nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(
            context.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(key.data()),
            reinterpret_cast<const unsigned char *>(message.nonce.data())) != 1 ||
        (!aad.empty() &&
         EVP_EncryptUpdate(
             context.get(), nullptr, &length,
             reinterpret_cast<const unsigned char *>(aad.data()),
             static_cast<int>(aad.size())) != 1) ||
        (!plain.empty() &&
         EVP_EncryptUpdate(
             context.get(),
             reinterpret_cast<unsigned char *>(message.ciphertext.data()),
             &length,
             reinterpret_cast<const unsigned char *>(plain.data()),
             static_cast<int>(plain.size())) != 1))
        return false;
    total = length;
    if (EVP_EncryptFinal_ex(
            context.get(),
            reinterpret_cast<unsigned char *>(message.ciphertext.data()) + total,
            &length) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_AEAD_GET_TAG,
            static_cast<int>(message.tag.size()), message.tag.data()) != 1)
        return false;
    message.ciphertext.resize(static_cast<std::size_t>(total + length));
    return true;
}

bool PeerIdentity::decrypt(const std::string &key, const std::string &aad,
                           const PeerAeadMessage &message,
                           std::string &plain) const {
    if (key.size() != kAeadKeyBytes ||
        message.nonce.size() != kAeadNonceBytes ||
        message.tag.size() != kAeadTagBytes ||
        !validIntLength(aad.size()) ||
        !validIntLength(message.ciphertext.size()))
        return false;
    CipherContext context(EVP_CIPHER_CTX_new());
    int length = 0;
    int total = 0;
    std::string output(message.ciphertext.size(), '\0');
    if (!context ||
        EVP_DecryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(message.nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(
            context.get(), nullptr, nullptr,
            reinterpret_cast<const unsigned char *>(key.data()),
            reinterpret_cast<const unsigned char *>(message.nonce.data())) != 1 ||
        (!aad.empty() &&
         EVP_DecryptUpdate(
             context.get(), nullptr, &length,
             reinterpret_cast<const unsigned char *>(aad.data()),
             static_cast<int>(aad.size())) != 1) ||
        (!message.ciphertext.empty() &&
         EVP_DecryptUpdate(
             context.get(),
             reinterpret_cast<unsigned char *>(output.data()), &length,
             reinterpret_cast<const unsigned char *>(message.ciphertext.data()),
             static_cast<int>(message.ciphertext.size())) != 1))
        return false;
    total = length;
    if (EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_AEAD_SET_TAG,
            static_cast<int>(message.tag.size()),
            const_cast<char *>(message.tag.data())) != 1 ||
        EVP_DecryptFinal_ex(
            context.get(),
            reinterpret_cast<unsigned char *>(output.data()) + total,
            &length) != 1)
        return false;
    output.resize(static_cast<std::size_t>(total + length));
    plain = std::move(output);
    return true;
}

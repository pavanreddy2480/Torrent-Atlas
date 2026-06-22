#pragma once

#include <memory>
#include <string>

struct PeerAeadMessage {
    std::string nonce;
    std::string ciphertext;
    std::string tag;
};

class PeerIdentity {
public:
    static std::unique_ptr<PeerIdentity> loadOrCreate(
        const std::string &identityName);

    ~PeerIdentity();
    PeerIdentity(PeerIdentity &&) noexcept;
    PeerIdentity &operator=(PeerIdentity &&) noexcept;
    PeerIdentity(const PeerIdentity &) = delete;
    PeerIdentity &operator=(const PeerIdentity &) = delete;

    std::string publicHex() const;
    std::string signHex(const std::string &message) const;
    bool verifyHex(const std::string &message, const std::string &signatureHex,
                   const std::string &publicKeyHex) const;

    bool generateEphemeral(std::string &privateKey,
                           std::string &publicKeyHex) const;
    bool deriveEphemeralSecret(const std::string &privateKey,
                               const std::string &peerPublicKeyHex,
                               std::string &secret) const;
    std::string deriveSessionKey(const std::string &sharedSecret,
                                 const std::string &transcript) const;

    bool encrypt(const std::string &key, const std::string &aad,
                 const std::string &plain, PeerAeadMessage &message) const;
    bool decrypt(const std::string &key, const std::string &aad,
                 const PeerAeadMessage &message, std::string &plain) const;

private:
    struct Impl;
    explicit PeerIdentity(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

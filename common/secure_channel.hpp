#pragma once

// Client <-> tracker channel, on top of the length-prefixed frames in
// protocol.hpp: a one-round-trip handshake per connection. Both sides send a
// fresh X25519 public key, a random nonce and a timestamp. The tracker signs
// the whole exchange with the cluster's Ed25519 identity key, which clients
// know in advance from client.conf. The session key is
// SHA-256(X25519 secret || transcript), and the request and reply are
// AES-256-GCM under that key. Fresh keys from both sides make a recorded
// connection useless to replay.
//
// Tracker <-> tracker Raft traffic uses mutual TLS instead (raft_tracker.hpp).

#include "protocol.hpp"
#include "secure_crypto.hpp"

#include <ctime>
#include <fstream>
#include <sys/stat.h>

// Generous on purpose: replay safety comes from fresh keys and nonces; the
// timestamp only bounds how long a captured peer request stays usable.
static constexpr long long FRESHNESS_WINDOW_SECONDS = 300;

inline long long unixSeconds() { return static_cast<long long>(std::time(nullptr)); }

inline bool parseFreshTimestamp(const std::string &text, long long &value) {
    u64 parsed = 0;
    if (!parseUnsignedDecimal(text, parsed) ||
        parsed > static_cast<u64>(std::numeric_limits<long long>::max()))
        return false;
    value = static_cast<long long>(parsed);
    long long age = unixSeconds() - value;
    return age <= FRESHNESS_WINDOW_SECONDS && age >= -FRESHNESS_WINDOW_SECONDS;
}

// Key files hold one hex-encoded key of the expected size.
inline bool readKeyFile(const std::string &path, std::size_t size, std::string &key) {
    std::ifstream input(path);
    std::string hex, extra;
    if (!(input >> hex) || (input >> extra)) return false;
    return hexDecode(hex, key) && key.size() == size;
}

inline bool writeKeyFile(const std::string &path, const std::string &key, bool secret) {
    {
        std::ofstream output(path, std::ios::trunc);
        if (!(output << hexEncode(key) << '\n')) return false;
    }
    return !secret || chmod(path.c_str(), 0600) == 0;
}

// ---- Client <-> tracker channel ----

inline std::string handshakeTranscript(const std::string &clientHello,
                                       const std::string &serverFields) {
    return "torrent-handshake-v1|" + clientHello + "|" + serverFields;
}

inline bool sealedSend(int fd, const std::string &key, const std::string &direction,
                       const std::string &plain) {
    AesGcmMessage message;
    return aes256GcmEncrypt(key, direction, plain, message) &&
           sendFrame(fd, message.nonce + message.tag + message.ciphertext);
}

inline bool sealedReceive(int fd, const std::string &key, const std::string &direction,
                          std::string &plain) {
    std::string frame;
    if (!receiveFrame(fd, frame) || frame.size() < 28) return false;
    AesGcmMessage message{frame.substr(0, 12), frame.substr(28), frame.substr(12, 16)};
    return aes256GcmDecrypt(key, direction, message, plain);
}

// Client side. Fails if the server's signature does not verify under the
// pinned public key, or its timestamp is stale.
inline bool clientHandshake(int fd, const std::string &serverPublicKey,
                            std::string &sessionKey) {
    std::string ephemeralPrivate, ephemeralPublic;
    std::string nonce = randomBytes(16);
    if (nonce.size() != 16 || !x25519KeyPair(ephemeralPrivate, ephemeralPublic))
        return false;
    std::string hello = "HELLO|" + hexEncode(ephemeralPublic) + "|" + hexEncode(nonce) +
                        "|" + std::to_string(unixSeconds());
    std::string reply;
    if (!sendFrame(fd, hello) || !receiveFrame(fd, reply)) return false;
    std::vector<std::string> fields = split(reply, '|');
    std::string serverPublic, serverNonce, signature;
    long long timestamp = 0;
    if (fields.size() != 5 || fields[0] != "HELLO" ||
        !hexDecode(fields[1], serverPublic) || serverPublic.size() != 32 ||
        !hexDecode(fields[2], serverNonce) || serverNonce.size() != 16 ||
        !parseFreshTimestamp(fields[3], timestamp) ||
        !hexDecode(fields[4], signature))
        return false;
    std::string transcript = handshakeTranscript(
        hello, fields[1] + "|" + fields[2] + "|" + fields[3]);
    if (!ed25519Verify(serverPublicKey, transcript, signature)) return false;
    std::string shared = x25519SharedSecret(ephemeralPrivate, serverPublic);
    secureErase(ephemeralPrivate);
    if (shared.empty()) return false;
    sessionKey = sha256(shared + transcript);
    secureErase(shared);
    return sessionKey.size() == 32;
}

// Server side (tracker).
inline bool serverHandshake(int fd, const std::string &identityPrivateKey,
                            std::string &sessionKey) {
    std::string hello;
    if (!receiveFrame(fd, hello)) return false;
    std::vector<std::string> fields = split(hello, '|');
    std::string clientPublic, clientNonce;
    long long timestamp = 0;
    if (fields.size() != 4 || fields[0] != "HELLO" ||
        !hexDecode(fields[1], clientPublic) || clientPublic.size() != 32 ||
        !hexDecode(fields[2], clientNonce) || clientNonce.size() != 16 ||
        !parseFreshTimestamp(fields[3], timestamp))
        return false;
    std::string ephemeralPrivate, ephemeralPublic;
    std::string nonce = randomBytes(16);
    if (nonce.size() != 16 || !x25519KeyPair(ephemeralPrivate, ephemeralPublic))
        return false;
    std::string serverFields = hexEncode(ephemeralPublic) + "|" + hexEncode(nonce) + "|" +
                               std::to_string(unixSeconds());
    std::string transcript = handshakeTranscript(hello, serverFields);
    std::string signature = ed25519Sign(identityPrivateKey, transcript);
    if (signature.empty() ||
        !sendFrame(fd, "HELLO|" + serverFields + "|" + hexEncode(signature)))
        return false;
    std::string shared = x25519SharedSecret(ephemeralPrivate, clientPublic);
    secureErase(ephemeralPrivate);
    if (shared.empty()) return false;
    sessionKey = sha256(shared + transcript);
    secureErase(shared);
    return sessionKey.size() == 32;
}

// One encrypted request/response with a tracker.
inline bool secureTrackerCall(const Endpoint &endpoint, const std::string &serverPublicKey,
                         const std::string &request, std::string &response,
                         int timeoutSeconds = 5) {
    UniqueFd fd(connectTcp(endpoint.ip, endpoint.port, timeoutSeconds));
    std::string sessionKey;
    bool ok = fd && clientHandshake(fd.get(), serverPublicKey, sessionKey) &&
              sealedSend(fd.get(), sessionKey, "client->tracker", request) &&
              sealedReceive(fd.get(), sessionKey, "tracker->client", response);
    secureErase(sessionKey);
    return ok;
}

#pragma once

// Client <-> tracker channel, on top of Socket frames: a one-round-trip
// handshake per connection. Both sides send a fresh X25519 public key, a
// random nonce and a timestamp. The tracker signs the whole exchange with the
// cluster's Ed25519 identity key, which clients know in advance from
// client.conf. The session key is SHA-256(X25519 secret || transcript), and
// every message after the handshake is AES-256-GCM under that key. Fresh keys
// from both sides make a recorded connection useless to replay.
//
// Tracker <-> tracker Raft traffic uses mutual TLS instead (raft_node.cpp).

#include "net.hpp"

#include <optional>
#include <string>

class SecureChannel {
public:
    // Client side. Fails unless the tracker's signature verifies under the
    // pinned public key and its timestamp is fresh.
    static std::optional<SecureChannel> connect(Socket socket, const std::string &trackerPublicKey);
    // Tracker side.
    static std::optional<SecureChannel> accept(Socket socket, const std::string &identityPrivateKey);

    SecureChannel(SecureChannel &&) = default;
    SecureChannel &operator=(SecureChannel &&) = default;
    ~SecureChannel();

    bool send(const std::string &plain) { return socket_.sendFrame(seal(plain)); }
    bool receive(std::string &plain);

    // The frame send() writes: nonce || tag || ciphertext.
    std::string seal(const std::string &plain) const;
    Socket &socket() { return socket_; }

private:
    SecureChannel(Socket socket, std::string key, bool client);

    Socket socket_;
    std::string key_;
    std::string sendLabel_;
    std::string receiveLabel_;
};

// One encrypted request and reply with a tracker.
bool callTracker(const Endpoint &tracker, const std::string &trackerPublicKey,
                 const std::string &request, std::string &response, int timeoutSeconds = 5);

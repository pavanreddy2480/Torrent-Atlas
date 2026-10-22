#pragma once

// The tracker's Ed25519 identity key. It signs every client handshake (see
// secure_channel.hpp), and clients pin its public key from client.conf.
// torrent_keygen creates it once:
//   <keys>/tracker_identity.key   hex private key, mode 0600
//   <client.conf>                 the tracker's address and hex public key

#include "common/net/net.hpp"

#include <optional>
#include <string>

class TrackerIdentity {
public:
    // Creates a new key in keysDir and a client.conf pointing at tracker.
    static bool create(const Endpoint &tracker, const std::string &keysDir,
                       const std::string &clientConfPath, std::string &error);
    static std::optional<TrackerIdentity> load(const std::string &keysDir);

    const std::string &privateKey() const { return privateKey_; }   // raw 32 bytes

private:
    std::string privateKey_;
};

#pragma once

/// @file tracker_identity.hpp
/// The tracker's Ed25519 identity key. It signs every client handshake (see
/// secure_channel.hpp), and clients pin its public key from client.conf.
///
/// torrent_keygen creates it once:
///   <keys>/tracker_identity.key   hex private key, mode 0600
///   <client.conf>                 the tracker's address and hex public key

#include "common/net/net.hpp"

#include <optional>
#include <string>

/// Holds the tracker's private signing key in memory.
class TrackerIdentity {
public:
    /// Generates a new key pair. Writes the private key to keysDir (created
    /// with mode 0700 if missing; the key file gets 0600) and a client.conf
    /// naming tracker and the public key. Overwrites existing files.
    /// @param error Receives a human-readable message on failure.
    /// @return true if both files were written.
    static bool create(const Endpoint &tracker, const std::string &keysDir,
                       const std::string &clientConfPath, std::string &error);

    /// Reads <keysDir>/tracker_identity.key.
    /// @return The identity, or std::nullopt if the file is missing or does
    ///         not hold exactly one 32-byte hex key.
    static std::optional<TrackerIdentity> load(const std::string &keysDir);

    /// @return The raw 32-byte Ed25519 private key.
    const std::string &privateKey() const { return privateKey_; }

private:
    std::string privateKey_;
};

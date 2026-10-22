#pragma once

/// @file client_config.hpp
/// client.conf: where the tracker is and which key it must prove it holds.
///
/// Format (whitespace-separated, exactly two tokens):
///   127.0.0.1:6000
///   <64 hex digits: the tracker's Ed25519 public key>
/// torrent_keygen writes it; the client reads it at startup.

#include "common/net/net.hpp"

#include <optional>
#include <string>

/// The contents of client.conf.
struct ClientConfig {
    Endpoint tracker;               ///< The tracker's address.
    std::string trackerPublicKey;   ///< Raw 32-byte Ed25519 key to pin.

    /// Reads client.conf.
    /// @return The config, or std::nullopt if the file is missing, has the
    ///         wrong number of tokens, or holds an invalid address or key.
    static std::optional<ClientConfig> load(const std::string &path);

    /// Writes this config to path, replacing any existing file.
    /// @return false if the file could not be written.
    bool save(const std::string &path) const;
};

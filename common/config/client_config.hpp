#pragma once

// client.conf: the tracker's IP:PORT, then its hex Ed25519 public key.
// torrent_keygen writes it; the client reads it.

#include "common/net/net.hpp"

#include <optional>
#include <string>

struct ClientConfig {
    Endpoint tracker;
    std::string trackerPublicKey;   // raw 32 bytes

    static std::optional<ClientConfig> load(const std::string &path);
    bool save(const std::string &path) const;
};

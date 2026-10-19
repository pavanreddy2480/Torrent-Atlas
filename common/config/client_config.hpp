#pragma once

// client.conf: one tracker IP:PORT per line, then the cluster's hex Ed25519
// public key. torrent_keygen writes it; the client reads it.

#include "common/net/net.hpp"

#include <optional>
#include <string>
#include <vector>

struct ClientConfig {
    std::vector<Endpoint> trackers;
    std::string trackerPublicKey;   // raw 32 bytes

    static std::optional<ClientConfig> load(const std::string &path);
    bool save(const std::string &path) const;
};

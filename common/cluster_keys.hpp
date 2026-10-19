#pragma once

// Every key a deployment needs, created by torrent_keygen from cluster.conf:
//   <keys>/ca.crt, ca.key          cluster certificate authority (P-256)
//   <keys>/node<id>.crt, .key      each tracker's TLS certificate, CN=torrent-node-<id>
//   <keys>/tracker_identity.key    Ed25519 key the trackers sign client handshakes with
//   <client.conf>                  every tracker's client address, then the
//                                  Ed25519 public key clients pin
// Private keys are written with mode 0600.

#include "cluster_config.hpp"

#include <optional>
#include <string>

bool generateClusterKeys(const ClusterConfig &cluster, const std::string &keysDir,
                         const std::string &clientConfPath, std::string &error);

// The files one tracker node loads at startup.
struct NodeKeys {
    std::string caCertFile;
    std::string certFile;
    std::string keyFile;
    std::string identityKey;   // raw Ed25519 private key

    static std::optional<NodeKeys> load(const std::string &keysDir, int nodeId);
};

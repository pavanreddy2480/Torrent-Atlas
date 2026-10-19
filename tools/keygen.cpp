// torrent_keygen <cluster.conf> <keys-dir> <client.conf>
// Creates the cluster CA, one TLS certificate per tracker, the trackers'
// client-handshake identity key, and the client config. See cluster_keys.hpp.

#include "common/config/cluster_keys.hpp"

#include <iostream>

int main(int argc, char **argv) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <cluster.conf> <keys-dir> <client.conf>\n";
        return 1;
    }
    std::optional<ClusterConfig> cluster = ClusterConfig::load(argv[1]);
    if (!cluster) {
        std::cerr << "could not read " << argv[1] << '\n';
        return 1;
    }
    std::string error;
    if (!generateClusterKeys(*cluster, argv[2], argv[3], error)) {
        std::cerr << error << '\n';
        return 1;
    }
    std::cout << "wrote CA, " << cluster->members().size()
              << " node certificates and the tracker identity key to " << argv[2] << ", and "
              << argv[3] << '\n';
    return 0;
}

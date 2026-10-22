/// @file client/main.cpp
/// client <peer IP:PORT> <client.conf>
///
/// Starts a client: a peer server on IP:PORT and a command prompt on
/// stdin/stdout. client.conf (from torrent_keygen) says where the tracker is
/// and which public key it must prove it holds. Exit code 1 on bad
/// arguments or if the peer server can't start.

#include "client/client.hpp"

#include <iostream>

int main(int argc, char **argv) {
    std::optional<Endpoint> self = argc == 3 ? Endpoint::parse(argv[1]) : std::nullopt;
    std::optional<ClientConfig> config = argc == 3 ? ClientConfig::load(argv[2]) : std::nullopt;
    if (!self || !config) {
        std::cerr << "usage: " << argv[0] << " <peer-ip:port> client.conf\n"
                  << "client.conf holds the tracker's IP:PORT and public key; "
                     "torrent_keygen creates it\n";
        return 1;
    }
    Client client(*self, *config);
    return client.run(std::cin, std::cout);
}

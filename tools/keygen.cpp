/// @file tools/keygen.cpp
/// torrent_keygen <tracker IP:PORT> <keys-dir> <client.conf>
///
/// Creates the tracker's Ed25519 identity key in keys-dir and a client.conf
/// that points clients at IP:PORT and pins the matching public key. Run it
/// once, on the tracker's machine; give clients only client.conf. Running it
/// again replaces the key, so every client then needs the new client.conf.
/// See tracker_identity.hpp. Exit code 0 on success, 1 on error.

#include "common/config/tracker_identity.hpp"

#include <iostream>

int main(int argc, char **argv) {
    std::optional<Endpoint> tracker = argc == 4 ? Endpoint::parse(argv[1]) : std::nullopt;
    if (!tracker) {
        std::cerr << "usage: " << argv[0] << " <tracker-ip:port> <keys-dir> <client.conf>\n";
        return 1;
    }
    std::string error;
    if (!TrackerIdentity::create(*tracker, argv[2], argv[3], error)) {
        std::cerr << error << '\n';
        return 1;
    }
    std::cout << "wrote the tracker identity key to " << argv[2] << " and " << argv[3] << '\n';
    return 0;
}

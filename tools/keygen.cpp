// Creates the keys a deployment needs, in the given config directory:
//   cluster.key       shared HMAC key for the load balancer and trackers (secret)
//   lb_identity.key   load balancer's Ed25519 private key (secret)
//   client.conf       rewritten as "<LB IP:PORT>\n<LB public key>"
#include "../common/secure_channel.hpp"

#include <iostream>

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <config-dir>\n";
        return 1;
    }
    std::string dir = argv[1];
    std::string clientConf = dir + "/client.conf";
    std::string lbEndpoint = "127.0.0.1:5000";
    {
        std::ifstream input(clientConf);
        std::string token;
        Endpoint endpoint;
        if (input >> token && parseEndpoint(token, endpoint)) lbEndpoint = token;
    }

    std::string clusterKey = randomBytes(32);
    std::string identityPrivate, identityPublic;
    if (clusterKey.size() != 32 || !ed25519KeyPair(identityPrivate, identityPublic)) {
        std::cerr << "key generation failed\n";
        return 1;
    }
    if (!writeKeyFile(dir + "/cluster.key", clusterKey, true) ||
        !writeKeyFile(dir + "/lb_identity.key", identityPrivate, true)) {
        std::cerr << "could not write key files in " << dir << '\n';
        return 1;
    }
    std::ofstream output(clientConf, std::ios::trunc);
    if (!(output << lbEndpoint << '\n' << hexEncode(identityPublic) << '\n')) {
        std::cerr << "could not write " << clientConf << '\n';
        return 1;
    }
    std::cout << "wrote " << dir << "/cluster.key, " << dir << "/lb_identity.key and "
              << clientConf << '\n';
    return 0;
}

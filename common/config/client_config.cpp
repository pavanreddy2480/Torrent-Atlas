#include "common/config/client_config.hpp"

#include "common/encoding.hpp"

#include <fstream>

std::optional<ClientConfig> ClientConfig::load(const std::string &path) {
    std::ifstream input(path);
    std::string address, publicKey, extra;
    ClientConfig config;
    if (!(input >> address >> publicKey) || (input >> extra) ||
        !fromHex(publicKey, config.trackerPublicKey) || config.trackerPublicKey.size() != 32)
        return std::nullopt;
    std::optional<Endpoint> tracker = Endpoint::parse(address);
    if (!tracker) return std::nullopt;
    config.tracker = *tracker;
    return config;
}

bool ClientConfig::save(const std::string &path) const {
    std::ofstream output(path, std::ios::trunc);
    output << tracker.toString() << '\n' << toHex(trackerPublicKey) << '\n';
    return static_cast<bool>(output);
}

#include "client_config.hpp"

#include "encoding.hpp"

#include <fstream>

std::optional<ClientConfig> ClientConfig::load(const std::string &path) {
    std::ifstream input(path);
    std::vector<std::string> tokens;
    for (std::string token; input >> token;) tokens.push_back(token);
    ClientConfig config;
    if (tokens.size() < 2 || !fromHex(tokens.back(), config.trackerPublicKey) ||
        config.trackerPublicKey.size() != 32)
        return std::nullopt;
    tokens.pop_back();
    for (const std::string &token : tokens) {
        std::optional<Endpoint> tracker = Endpoint::parse(token);
        if (!tracker) return std::nullopt;
        config.trackers.push_back(*tracker);
    }
    return config;
}

bool ClientConfig::save(const std::string &path) const {
    std::ofstream output(path, std::ios::trunc);
    for (const Endpoint &tracker : trackers) output << tracker.toString() << '\n';
    output << toHex(trackerPublicKey) << '\n';
    return static_cast<bool>(output);
}

#include "network_utils.hpp"

#include <fstream>

bool loadTrackerInfo(const std::string &path, std::vector<Endpoint> &trackers,
                     std::string &serverPublicKey) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<std::string> tokens;
    std::string token;
    while (input >> token) tokens.push_back(token);
    if (tokens.size() < 2) return false;
    std::string key;
    if (!hexDecode(tokens.back(), key) || key.size() != 32) return false;
    std::vector<Endpoint> loaded;
    for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
        Endpoint endpoint;
        if (!parseEndpoint(tokens[i], endpoint)) return false;
        loaded.push_back(endpoint);
    }
    trackers = std::move(loaded);
    serverPublicKey = std::move(key);
    return true;
}

#include "network_utils.hpp"

#include <fstream>

bool loadTrackerInfo(const std::string &path, Endpoint &tracker) {
    std::ifstream input(path);
    if (!input) return false;
    std::string token;
    Endpoint loaded;
    if (!(input >> token) || !parseEndpoint(token, loaded)) return false;
    if (input >> token) return false;
    tracker = std::move(loaded);
    return true;
}

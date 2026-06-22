#include "network_utils.hpp"

#include <fstream>

std::string endpointKey(const Endpoint &endpoint) {
    return endpoint.ip + ":" + std::to_string(endpoint.port);
}

bool parseEndpoint(const std::string &text, Endpoint &endpoint) {
    std::size_t colon = text.rfind(':');
    if (colon == std::string::npos) return false;
    endpoint.ip = text.substr(0, colon);
    try {
        endpoint.port = std::stoi(text.substr(colon + 1));
    } catch (...) {
        return false;
    }
    return !endpoint.ip.empty() && endpoint.port > 0 &&
           endpoint.port <= 65535;
}

bool loadTrackerInfo(const std::string &path,
                     std::vector<Endpoint> &trackers) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<Endpoint> loaded;
    std::string token;
    while (input >> token) {
        Endpoint endpoint;
        if (token.find(':') != std::string::npos) {
            if (!parseEndpoint(token, endpoint)) return false;
        } else {
            endpoint.ip = token;
            if (!(input >> endpoint.port) || endpoint.port <= 0 ||
                endpoint.port > 65535)
                return false;
        }
        loaded.push_back(endpoint);
    }
    if (loaded.size() != 2) return false;
    trackers = std::move(loaded);
    return true;
}

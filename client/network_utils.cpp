#include "network_utils.hpp"

#include <fstream>

bool loadTrackerInfo(const std::string &path, Endpoint &tracker,
                     std::string &serverPublicKey) {
    std::ifstream input(path);
    if (!input) return false;
    std::string token, keyHex, key;
    Endpoint loaded;
    if (!(input >> token) || !parseEndpoint(token, loaded)) return false;
    if (!(input >> keyHex) || !hexDecode(keyHex, key) || key.size() != 32) return false;
    if (input >> token) return false;
    tracker = std::move(loaded);
    serverPublicKey = std::move(key);
    return true;
}

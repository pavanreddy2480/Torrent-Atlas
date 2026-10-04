#pragma once

#include "protocol.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

struct ClusterMember {
    int id = 0;
    Endpoint client;   // where clients connect
    Endpoint raft;     // where other trackers connect
};

// cluster.conf: one line per node, "<id> <client IP:PORT> <raft IP:PORT>".
inline bool readClusterConfig(const std::string &path, std::vector<ClusterMember> &members) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<ClusterMember> loaded;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream fields(line);
        std::string idText, client, raft, extra;
        u64 id = 0;
        ClusterMember member;
        if (!(fields >> idText >> client >> raft) || (fields >> extra) ||
            !parseUnsignedDecimal(idText, id) || id == 0 || id > 1000 ||
            !parseEndpoint(client, member.client) || !parseEndpoint(raft, member.raft))
            return false;
        member.id = static_cast<int>(id);
        for (const auto &other : loaded)
            if (other.id == member.id) return false;
        loaded.push_back(member);
    }
    if (loaded.size() < 3 || loaded.size() % 2 == 0) return false;  // 3, 5, ...
    members = std::move(loaded);
    return true;
}

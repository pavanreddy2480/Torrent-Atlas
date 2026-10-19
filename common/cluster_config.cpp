#include "cluster_config.hpp"

#include "encoding.hpp"

#include <fstream>
#include <sstream>

std::optional<ClusterConfig> ClusterConfig::load(const std::string &path) {
    std::ifstream input(path);
    if (!input) return std::nullopt;
    ClusterConfig config;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream fields(line);
        std::string idText, client, raft, extra;
        u64 id = 0;
        if (!(fields >> idText >> client >> raft) || (fields >> extra) ||
            !parseU64(idText, id) || id == 0 || id > 1000)
            return std::nullopt;
        std::optional<Endpoint> clientEndpoint = Endpoint::parse(client);
        std::optional<Endpoint> raftEndpoint = Endpoint::parse(raft);
        if (!clientEndpoint || !raftEndpoint || config.find(static_cast<int>(id)))
            return std::nullopt;
        config.members_.push_back({static_cast<int>(id), *clientEndpoint, *raftEndpoint});
    }
    if (config.members_.size() < 3 || config.members_.size() % 2 == 0) return std::nullopt;
    return config;
}

const ClusterMember *ClusterConfig::find(int id) const {
    for (const ClusterMember &member : members_)
        if (member.id == id) return &member;
    return nullptr;
}

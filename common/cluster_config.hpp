#pragma once

// cluster.conf lists the tracker nodes, one per line:
//   <id> <client IP:PORT> <raft IP:PORT>
// Lines starting with '#' are comments. A cluster needs an odd number of
// nodes, three or more, so that a majority always exists.

#include "net.hpp"

#include <optional>
#include <string>
#include <vector>

struct ClusterMember {
    int id = 0;
    Endpoint client;   // where clients connect
    Endpoint raft;     // where other trackers connect
};

class ClusterConfig {
public:
    static std::optional<ClusterConfig> load(const std::string &path);

    const std::vector<ClusterMember> &members() const { return members_; }
    const ClusterMember *find(int id) const;

private:
    std::vector<ClusterMember> members_;
};

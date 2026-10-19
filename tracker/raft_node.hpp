#pragma once

// A tracker node: one member of a NuRaft cluster.
//
// Every state-changing command becomes a Raft log entry. The leader picks the
// random and time-dependent inputs (password salt, new session ID, current
// time), so each replica applies the entry identically. A command is
// acknowledged only after a majority of nodes has stored it, and NuRaft elects
// a new leader if the current one fails. Reads are answered by the leader,
// once it has applied every entry committed before it was elected.
// Followers answer every client request with REDIRECT <leader address>.
//
// Node-to-node Raft traffic uses mutual TLS with certificates from
// torrent_keygen.

#include "tracker_state.hpp"

#include "../common/cluster_config.hpp"
#include "../common/cluster_keys.hpp"

#include <libnuraft/nuraft.hxx>

class RaftNode {
public:
    RaftNode(ClusterMember self, ClusterConfig cluster, NodeKeys keys);

    bool start(const std::string &dataDir);
    void stop() { launcher_.shutdown(5); }

    // One decrypted client request "C\t<session>\t<command>"; returns
    // "<response>\t<session>".
    std::string handle(const std::string &request);

private:
    std::string leaderRedirect(u64 session) const;

    ClusterMember self_;
    ClusterConfig cluster_;
    NodeKeys keys_;
    TrackerState state_;
    nuraft::raft_launcher launcher_;
    nuraft::ptr<nuraft::raft_server> raft_;
};

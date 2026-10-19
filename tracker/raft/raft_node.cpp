#include "tracker/raft/raft_node.hpp"

#include "tracker/raft/log_command.hpp"
#include "tracker/raft/raft_storage.hpp"
#include "tracker/raft/state_machine.hpp"
#include "tracker/raft/storage_io.hpp"

#include <openssl/ssl.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace nuraft;

namespace {

// Both sides of a node-to-node connection must present a certificate signed
// by the cluster CA.
SSL_CTX *makeTlsContext(bool server, const NodeKeys &keys) {
    SSL_CTX *context = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!context) return nullptr;
    SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_chain_file(context, keys.certFile.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, keys.keyFile.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1 ||
        SSL_CTX_load_verify_locations(context, keys.caCertFile.c_str(), nullptr) != 1) {
        SSL_CTX_free(context);
        return nullptr;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    return context;
}

// NuRaft log lines go to stderr when TORRENT_RAFT_LOG is set (1 = errors ... 6 = trace).
class StderrLogger : public logger {
public:
    explicit StderrLogger(int level) : level_(level) {}
    void put_details(int level, const char *, const char *function, size_t line,
                     const std::string &message) override {
        if (level <= level_)
            std::cerr << "[raft " << level << "] " << function << ':' << line << ' ' << message
                      << '\n';
    }
    void set_level(int level) override { level_ = level; }
    int get_level() override { return level_; }

private:
    int level_;
};

std::string withSession(const std::string &response, u64 session) {
    return response + "\t" + std::to_string(session);
}

}  // namespace

RaftNode::RaftNode(ClusterMember self, ClusterConfig cluster, NodeKeys keys)
    : self_(std::move(self)), cluster_(std::move(cluster)), keys_(std::move(keys)) {}

bool RaftNode::start(const std::string &dataDir) {
    auto config = cs_new<cluster_config>();
    for (const ClusterMember &member : cluster_.members())
        config->get_servers().push_back(cs_new<srv_config>(member.id, member.raft.toString()));
    auto stateManager = cs_new<FileStateManager>(self_.id, dataDir, config);
    auto machine = cs_new<TrackerStateMachine>(state_, dataDir + "/snapshot.bin");

    asio_service::options asio;
    asio.thread_pool_size_ = 4;
    asio.enable_ssl_ = true;
    NodeKeys keys = keys_;
    asio.ssl_context_provider_server_ = [keys] { return makeTlsContext(true, keys); };
    asio.ssl_context_provider_client_ = [keys] { return makeTlsContext(false, keys); };
    // Called for every certificate in the peer's chain: the CA and the node.
    asio.verify_sn_ = [](const std::string &subject) {
        return subject == "/CN=torrent-cluster-ca" || subject.rfind("/CN=torrent-node-", 0) == 0;
    };

    raft_params params;
    params.heart_beat_interval_ = 100;
    params.election_timeout_lower_bound_ = 400;
    params.election_timeout_upper_bound_ = 800;
    params.snapshot_distance_ = 1000;
    params.reserved_log_items_ = 1000;
    params.client_req_timeout_ = 3000;
    params.return_method_ = raft_params::blocking;

    ptr<logger> log;
    if (const char *level = std::getenv("TORRENT_RAFT_LOG"))
        log = cs_new<StderrLogger>(std::atoi(level));
    raft_ = launcher_.init(machine, stateManager, log, self_.raft.port, asio, params);
    if (!raft_) {
        std::cerr << "raft listener could not start on port " << self_.raft.port << '\n';
        return false;
    }
    for (int attempt = 0; attempt < 100 && !raft_->is_initialized(); ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return raft_->is_initialized();
}

std::string RaftNode::leaderRedirect(u64 session) const {
    const ClusterMember *leader = cluster_.find(raft_->get_leader());
    if (leader && leader->id != self_.id)
        return withSession("REDIRECT " + leader->client.toString(), session);
    return withSession("ERR no leader elected yet; retry", session);
}

std::string RaftNode::handle(const std::string &request) {
    std::vector<std::string> fields = split(request, '\t');
    LogCommand entry;
    if (fields.size() < 3 || fields[0] != "C" || !parseU64(fields[1], entry.session))
        return "ERR malformed request\t0";
    entry.command = join(std::vector<std::string>(fields.begin() + 2, fields.end()), '\t');

    if (!raft_->is_leader()) return leaderRedirect(entry.session);
    if (!TrackerState::isMutation(entry.command)) {
        // A new leader may not have applied every committed entry yet.
        if (!raft_->is_leader_sm_fully_caught_up())
            return withSession("ERR leader catching up; retry", entry.session);
        CommandResult result = state_.apply(entry.session, entry.command);
        return withSession(result.response, result.session);
    }
    entry.context = ApplyContext::fresh();
    auto result = raft_->append_entries({storage_io::toBuffer(entry.encode())});
    if (!result->get_accepted()) return leaderRedirect(entry.session);
    if (result->get_result_code() != cmd_result_code::OK || !result->get())
        return withSession("ERR write not committed by a majority; retry", entry.session);
    return storage_io::toString(*result->get());
}

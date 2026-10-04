#pragma once

// A tracker node: one member of a NuRaft cluster.
//
// Every state-changing command becomes a Raft log entry. The leader picks the
// random and time-dependent inputs (password salt, new session ID, current
// time), so each replica applies the entry identically. A command is
// acknowledged only after a majority of nodes has stored it, and NuRaft elects
// a new leader if the current one fails. Reads are answered by the leader.
// Followers answer every client request with REDIRECT <leader address>.
//
// Node-to-node Raft traffic uses mutual TLS with certificates from
// torrent_keygen. Client traffic uses the signed X25519 handshake in
// secure_channel.hpp.

#include "raft_storage.hpp"
#include "../common/cluster_config.hpp"
#include "../common/secure_channel.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <poll.h>
#include <sstream>
#include <thread>

// ---- Log entry encoding: "<session>\t<salt hex>\t<new session>\t<now>\t<command>" ----

inline std::string encodeCommandEntry(u64 session, const ApplyContext &context,
                                      const std::string &command) {
    return std::to_string(session) + "\t" + hexEncode(context.salt) + "\t" +
           std::to_string(context.newSession) + "\t" + std::to_string(context.now) +
           "\t" + command;
}

inline bool decodeCommandEntry(const std::string &entry, u64 &session,
                               ApplyContext &context, std::string &command) {
    std::vector<std::string> fields = split(entry, '\t');
    u64 now = 0;
    if (fields.size() < 5 || !parseUnsignedDecimal(fields[0], session) ||
        !hexDecode(fields[1], context.salt) ||
        !parseUnsignedDecimal(fields[2], context.newSession) ||
        !parseUnsignedDecimal(fields[3], now))
        return false;
    context.now = static_cast<long long>(now);
    command = fields[4];
    for (std::size_t i = 5; i < fields.size(); ++i) command += "\t" + fields[i];
    return true;
}

class TrackerStateMachine : public nuraft::state_machine {
    using buffer = nuraft::buffer;
    template <typename T> using ptr = nuraft::ptr<T>;

    TrackerState &state_;
    std::string snapshotPath_;
    std::atomic<u64> lastCommitted_{0};
    std::mutex snapshotMutex_;
    ptr<nuraft::snapshot> lastSnapshot_;
    std::string lastSnapshotData_;   // serialized state at lastSnapshot_
    std::string incoming_;           // snapshot chunks being received
    static constexpr std::size_t CHUNK = 1024 * 1024;

    void persistLocked() {
        std::string meta = raft_storage::bufferString(*lastSnapshot_->serialize());
        std::string data;
        raft_storage::putU64(data, meta.size());
        data += meta + lastSnapshotData_;
        raft_storage::writeFileAtomic(snapshotPath_, data);
    }

public:
    TrackerStateMachine(TrackerState &state, std::string snapshotPath)
        : state_(state), snapshotPath_(std::move(snapshotPath)) {
        // Restart: load the last snapshot; NuRaft replays newer log entries.
        std::string data;
        std::size_t pos = 0;
        u64 metaLength = 0;
        if (raft_storage::readFile(snapshotPath_, data) &&
            raft_storage::getU64(data, pos, metaLength) && data.size() >= pos + metaLength) {
            ptr<buffer> meta = raft_storage::stringBuffer(data.substr(pos, metaLength));
            ptr<nuraft::snapshot> snapshot = nuraft::snapshot::deserialize(*meta);
            std::string stateData = data.substr(pos + metaLength);
            if (snapshot && state_.replaceFromSnapshot(stateData)) {
                lastSnapshot_ = snapshot;
                lastSnapshotData_ = std::move(stateData);
                lastCommitted_ = snapshot->get_last_log_idx();
            }
        }
    }

    ptr<buffer> commit(const nuraft::ulong logIndex, buffer &data) override {
        u64 session = 0;
        ApplyContext context;
        std::string command;
        std::string response;
        if (!decodeCommandEntry(raft_storage::bufferString(data), session, context, command)) {
            response = "ERR corrupt log entry\t" + std::to_string(session);
        } else {
            HandleResult result = state_.handle(session, command, false, context);
            response = result.response + "\t" + std::to_string(result.session);
        }
        lastCommitted_ = logIndex;
        return raft_storage::stringBuffer(response);
    }

    void commit_config(const nuraft::ulong logIndex,
                       ptr<nuraft::cluster_config> &) override {
        lastCommitted_ = logIndex;
    }

    ptr<buffer> pre_commit(const nuraft::ulong, buffer &) override { return nullptr; }
    void rollback(const nuraft::ulong, buffer &) override {}

    nuraft::ulong last_commit_index() override { return lastCommitted_; }

    ptr<nuraft::snapshot> last_snapshot() override {
        std::lock_guard<std::mutex> lock(snapshotMutex_);
        return lastSnapshot_;
    }

    void create_snapshot(nuraft::snapshot &snapshot,
                         nuraft::async_result<bool>::handler_type &whenDone) override {
        {
            // Runs on the commit thread, so the state is exactly at this index.
            std::lock_guard<std::mutex> lock(snapshotMutex_);
            ptr<buffer> meta = snapshot.serialize();
            lastSnapshot_ = nuraft::snapshot::deserialize(*meta);
            lastSnapshotData_ = state_.serialize();
            persistLocked();
        }
        bool ok = true;
        ptr<std::exception> error;
        whenDone(ok, error);
    }

    // Leader side of a snapshot transfer: send the state in 1 MiB chunks.
    int read_logical_snp_obj(nuraft::snapshot &snapshot, void *&, nuraft::ulong objectId,
                             ptr<buffer> &dataOut, bool &isLast) override {
        std::lock_guard<std::mutex> lock(snapshotMutex_);
        if (!lastSnapshot_ ||
            lastSnapshot_->get_last_log_idx() != snapshot.get_last_log_idx()) {
            dataOut = nullptr;
            isLast = true;
            return -1;
        }
        std::size_t offset = static_cast<std::size_t>(objectId) * CHUNK;
        std::string chunk = offset < lastSnapshotData_.size()
            ? lastSnapshotData_.substr(offset, CHUNK) : std::string();
        dataOut = raft_storage::stringBuffer(chunk);
        isLast = offset + CHUNK >= lastSnapshotData_.size();
        return 0;
    }

    // Follower side: collect chunks, then apply_snapshot installs them.
    void save_logical_snp_obj(nuraft::snapshot &, nuraft::ulong &objectId, buffer &data,
                              bool isFirst, bool) override {
        std::lock_guard<std::mutex> lock(snapshotMutex_);
        if (isFirst) incoming_.clear();
        incoming_ += raft_storage::bufferString(data);
        ++objectId;
    }

    bool apply_snapshot(nuraft::snapshot &snapshot) override {
        std::lock_guard<std::mutex> lock(snapshotMutex_);
        if (!state_.replaceFromSnapshot(incoming_)) return false;
        ptr<buffer> meta = snapshot.serialize();
        lastSnapshot_ = nuraft::snapshot::deserialize(*meta);
        lastSnapshotData_ = std::move(incoming_);
        incoming_.clear();
        lastCommitted_ = snapshot.get_last_log_idx();
        persistLocked();
        return true;
    }

    void free_user_snp_ctx(void *&) override {}
};

// ---- Mutual TLS between nodes ----

inline SSL_CTX *makeNodeTlsContext(bool server, const std::string &certFile,
                                   const std::string &keyFile, const std::string &caFile) {
    SSL_CTX *context = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!context) return nullptr;
    SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_chain_file(context, certFile.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, keyFile.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1 ||
        SSL_CTX_load_verify_locations(context, caFile.c_str(), nullptr) != 1) {
        SSL_CTX_free(context);
        return nullptr;
    }
    // Both sides must present a certificate signed by the cluster CA.
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    return context;
}

struct TrackerKeys {
    std::string caCert, nodeCert, nodeKey;
    std::string identityKey;   // Ed25519 key for the client handshake
};

inline bool loadTrackerKeys(const std::string &dir, int id, TrackerKeys &keys) {
    keys.caCert = dir + "/ca.crt";
    keys.nodeCert = dir + "/node" + std::to_string(id) + ".crt";
    keys.nodeKey = dir + "/node" + std::to_string(id) + ".key";
    struct stat info{};
    return stat(keys.caCert.c_str(), &info) == 0 && stat(keys.nodeCert.c_str(), &info) == 0 &&
           stat(keys.nodeKey.c_str(), &info) == 0 &&
           readKeyFile(dir + "/tracker_identity.key", 32, keys.identityKey);
}

// NuRaft log lines go to stderr when TORRENT_RAFT_LOG is set (1 = errors ... 6 = trace).
class StderrRaftLogger : public nuraft::logger {
    int level_;

public:
    explicit StderrRaftLogger(int level) : level_(level) {}
    void put_details(int level, const char *, const char *function, size_t line,
                     const std::string &message) override {
        if (level <= level_)
            std::cerr << "[raft " << level << "] " << function << ':' << line << ' '
                      << message << '\n';
    }
    void set_level(int level) override { level_ = level; }
    int get_level() override { return level_; }
};

// ---- The node ----

class RaftTracker {
    ClusterMember self_;
    std::vector<ClusterMember> members_;
    TrackerKeys keys_;
    TrackerState state_;
    nuraft::raft_launcher launcher_;
    nuraft::ptr<nuraft::raft_server> raft_;

    std::string leaderRedirect(u64 session) const {
        int leader = raft_ ? raft_->get_leader() : -1;
        for (const auto &member : members_)
            if (member.id == leader && leader != self_.id)
                return "REDIRECT " + endpointKey(member.client) + "\t" + std::to_string(session);
        return "ERR no leader elected yet; retry\t" + std::to_string(session);
    }

public:
    RaftTracker(ClusterMember self, std::vector<ClusterMember> members, TrackerKeys keys)
        : self_(std::move(self)), members_(std::move(members)), keys_(std::move(keys)) {}

    bool start(const std::string &dataDir) {
        using namespace nuraft;
        auto config = cs_new<cluster_config>();
        for (const auto &member : members_)
            config->get_servers().push_back(
                cs_new<srv_config>(member.id, endpointKey(member.raft)));
        auto stateManager = cs_new<raft_storage::FileStateManager>(self_.id, dataDir, config);
        auto machine = cs_new<TrackerStateMachine>(state_, dataDir + "/snapshot.bin");

        asio_service::options asio;
        asio.thread_pool_size_ = 4;
        asio.enable_ssl_ = true;
        TrackerKeys keys = keys_;
        asio.ssl_context_provider_server_ = [keys] {
            return makeNodeTlsContext(true, keys.nodeCert, keys.nodeKey, keys.caCert);
        };
        asio.ssl_context_provider_client_ = [keys] {
            return makeNodeTlsContext(false, keys.nodeCert, keys.nodeKey, keys.caCert);
        };
        // Called for every certificate in the peer's chain: the CA and the node.
        asio.verify_sn_ = [](const std::string &subject) {
            return subject == "/CN=torrent-cluster-ca" ||
                   subject.rfind("/CN=torrent-node-", 0) == 0;
        };

        raft_params params;
        params.heart_beat_interval_ = 100;
        params.election_timeout_lower_bound_ = 400;
        params.election_timeout_upper_bound_ = 800;
        params.snapshot_distance_ = 1000;
        params.reserved_log_items_ = 1000;
        params.client_req_timeout_ = 3000;
        params.return_method_ = raft_params::blocking;

        nuraft::ptr<nuraft::logger> logger;
        if (const char *level = std::getenv("TORRENT_RAFT_LOG"))
            logger = cs_new<StderrRaftLogger>(std::atoi(level));
        raft_ = launcher_.init(machine, stateManager, logger, self_.raft.port, asio, params);
        if (!raft_) {
            std::cerr << "raft listener could not start on port " << self_.raft.port << '\n';
            return false;
        }
        for (int attempt = 0; attempt < 100 && !raft_->is_initialized(); ++attempt)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return raft_->is_initialized();
    }

    void stop() { launcher_.shutdown(5); }

    // Handles one decrypted client request; returns "<response>\t<session>".
    std::string handle(const std::string &request) {
        std::vector<std::string> fields = split(request, '\t');
        u64 session = 0;
        if (fields.size() < 3 || fields[0] != "C" || !parseUnsignedDecimal(fields[1], session))
            return "ERR malformed request\t0";
        std::string command = fields[2];
        for (std::size_t i = 3; i < fields.size(); ++i) command += "\t" + fields[i];

        if (!raft_->is_leader()) return leaderRedirect(session);
        if (!isTrackerMutation(command)) {
            HandleResult result = state_.handle(session, command, false);
            return result.response + "\t" + std::to_string(result.session);
        }
        std::string entry = encodeCommandEntry(session, ApplyContext::fresh(), command);
        auto result = raft_->append_entries({raft_storage::stringBuffer(entry)});
        if (!result->get_accepted()) return leaderRedirect(session);
        if (result->get_result_code() != nuraft::cmd_result_code::OK || !result->get())
            return "ERR write not committed by a majority; retry\t" + std::to_string(session);
        return raft_storage::bufferString(*result->get());
    }

    void serveClient(int rawFd) {
        UniqueFd fd(rawFd);
        std::string sessionKey, request;
        if (serverHandshake(fd.get(), keys_.identityKey, sessionKey) &&
            sealedReceive(fd.get(), sessionKey, "client->tracker", request))
            sealedSend(fd.get(), sessionKey, "tracker->client", handle(request));
        secureErase(sessionKey);
    }

    const ClusterMember &self() const { return self_; }
};

inline int runTracker(int argc, char **argv) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " cluster.conf <node-id> <keys-dir> <data-dir>\n";
        return 1;
    }
    std::vector<ClusterMember> members;
    if (!readClusterConfig(argv[1], members)) {
        std::cerr << "cluster.conf needs an odd number (3 or more) of lines: "
                     "<id> <client IP:PORT> <raft IP:PORT>\n";
        return 1;
    }
    u64 id = 0;
    const ClusterMember *self = nullptr;
    if (parseUnsignedDecimal(argv[2], id))
        for (const auto &member : members)
            if (member.id == static_cast<int>(id)) self = &member;
    if (!self) {
        std::cerr << "node id not found in cluster.conf\n";
        return 1;
    }
    TrackerKeys keys;
    if (!loadTrackerKeys(argv[3], self->id, keys)) {
        std::cerr << "missing keys in " << argv[3] << " (run torrent_keygen)\n";
        return 1;
    }
    std::string dataDir = argv[4];
    for (std::size_t slash = dataDir.find('/', 1); ; slash = dataDir.find('/', slash + 1)) {
        ::mkdir(dataDir.substr(0, slash).c_str(), 0700);   // mkdir -p
        if (slash == std::string::npos) break;
    }

    RaftTracker tracker(*self, members, keys);
    int listener = createListener(self->client.ip, self->client.port);
    if (listener < 0) {
        perror("tracker listen");
        return 1;
    }
    if (!tracker.start(dataDir)) {
        std::cerr << "raft server failed to start\n";
        close(listener);
        return 1;
    }
    std::cerr << "Tracker " << self->id << " serving clients on " << endpointKey(self->client)
              << ", raft on " << endpointKey(self->raft) << '\n';

    bool running = true;
    bool monitorConsole = true;
    std::mutex workersMutex;
    std::condition_variable workersCondition;
    std::size_t activeWorkers = 0;
    while (running) {
        pollfd descriptors[2]{};
        descriptors[0].fd = listener;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = monitorConsole ? STDIN_FILENO : -1;
        descriptors[1].events = POLLIN;
        int ready = poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (monitorConsole && (descriptors[1].revents & (POLLIN | POLLHUP))) {
            std::string command;
            if (!std::getline(std::cin, command)) monitorConsole = false;
            else if (command == "quit") running = false;
        }
        if (!running) break;
        if (descriptors[0].revents & POLLIN) {
            int client = accept(listener, nullptr, nullptr);
            if (client < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                break;
            }
            timeval timeout{};
            timeout.tv_sec = 5;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            {
                std::lock_guard<std::mutex> lock(workersMutex);
                ++activeWorkers;
            }
            std::thread([&, client] {
                tracker.serveClient(client);
                {
                    std::lock_guard<std::mutex> lock(workersMutex);
                    --activeWorkers;
                }
                workersCondition.notify_all();
            }).detach();
        }
    }
    close(listener);
    {
        std::unique_lock<std::mutex> lock(workersMutex);
        workersCondition.wait(lock, [&] { return activeWorkers == 0; });
    }
    tracker.stop();
    return 0;
}

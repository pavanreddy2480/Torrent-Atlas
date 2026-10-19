#pragma once

// Durable storage NuRaft needs on each tracker, kept as small files in the
// node's data directory:
//   raft.log      every log entry (rewritten on truncation or compaction)
//   state.bin     current term and vote
//   config.bin    cluster membership
// (snapshot.bin belongs to TrackerStateMachine.)

#include <libnuraft/nuraft.hxx>

#include <map>
#include <mutex>
#include <string>

// The Raft log: an in-memory map backed by an append-only file.
// File: [u64 start index] then records [u64 index][u64 length][entry bytes].
class FileLogStore : public nuraft::log_store {
public:
    explicit FileLogStore(std::string path);

    nuraft::ulong next_slot() const override;
    nuraft::ulong start_index() const override;
    nuraft::ptr<nuraft::log_entry> last_entry() const override;
    nuraft::ulong append(nuraft::ptr<nuraft::log_entry> &entry) override;
    void write_at(nuraft::ulong index, nuraft::ptr<nuraft::log_entry> &entry) override;
    nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>> log_entries(nuraft::ulong start,
                                                                         nuraft::ulong end) override;
    nuraft::ptr<nuraft::log_entry> entry_at(nuraft::ulong index) override;
    nuraft::ulong term_at(nuraft::ulong index) override;
    nuraft::ptr<nuraft::buffer> pack(nuraft::ulong index, nuraft::int32 count) override;
    void apply_pack(nuraft::ulong index, nuraft::buffer &packed) override;
    bool compact(nuraft::ulong lastLogIndex) override;
    bool flush() override { return true; }   // every write is already fsynced

private:
    // All private methods expect mutex_ to be held.
    nuraft::ptr<nuraft::log_entry> entryOrDummy(nuraft::ulong index) const;
    bool rewrite();

    std::string path_;
    mutable std::mutex mutex_;
    std::map<nuraft::ulong, nuraft::ptr<nuraft::log_entry>> entries_;
    nuraft::ulong start_ = 1;
};

// Term, vote and cluster membership.
class FileStateManager : public nuraft::state_mgr {
public:
    FileStateManager(int id, std::string dir, nuraft::ptr<nuraft::cluster_config> initialConfig);

    nuraft::ptr<nuraft::cluster_config> load_config() override;
    void save_config(const nuraft::cluster_config &config) override;
    void save_state(const nuraft::srv_state &state) override;
    nuraft::ptr<nuraft::srv_state> read_state() override;
    nuraft::ptr<nuraft::log_store> load_log_store() override { return logStore_; }
    nuraft::int32 server_id() override { return id_; }
    void system_exit(const int exitCode) override { std::_Exit(exitCode); }

private:
    int id_;
    std::string dir_;
    nuraft::ptr<nuraft::cluster_config> initialConfig_;
    nuraft::ptr<FileLogStore> logStore_;
};

#pragma once

// Connects NuRaft to TrackerState: applies committed log entries, and saves,
// sends and installs snapshots. The latest snapshot is kept in snapshot.bin
// so a restarted node only replays newer log entries.

#include "tracker/state/tracker_state.hpp"

#include <libnuraft/nuraft.hxx>

#include <atomic>
#include <mutex>
#include <string>

class TrackerStateMachine : public nuraft::state_machine {
public:
    TrackerStateMachine(TrackerState &state, std::string snapshotPath);

    // Applies one LogCommand; the result buffer is "<response>\t<session>".
    nuraft::ptr<nuraft::buffer> commit(const nuraft::ulong logIndex, nuraft::buffer &data) override;
    void commit_config(const nuraft::ulong logIndex,
                       nuraft::ptr<nuraft::cluster_config> &) override {
        lastCommitted_ = logIndex;
    }
    nuraft::ptr<nuraft::buffer> pre_commit(const nuraft::ulong, nuraft::buffer &) override {
        return nullptr;
    }
    void rollback(const nuraft::ulong, nuraft::buffer &) override {}
    nuraft::ulong last_commit_index() override { return lastCommitted_; }

    nuraft::ptr<nuraft::snapshot> last_snapshot() override;
    void create_snapshot(nuraft::snapshot &snapshot,
                         nuraft::async_result<bool>::handler_type &whenDone) override;
    int read_logical_snp_obj(nuraft::snapshot &snapshot, void *&, nuraft::ulong objectId,
                             nuraft::ptr<nuraft::buffer> &dataOut, bool &isLast) override;
    void save_logical_snp_obj(nuraft::snapshot &, nuraft::ulong &objectId, nuraft::buffer &data,
                              bool isFirst, bool) override;
    bool apply_snapshot(nuraft::snapshot &snapshot) override;
    void free_user_snp_ctx(void *&) override {}

private:
    void loadSavedSnapshot();
    void saveSnapshotLocked();   // snapshotMutex_ held

    TrackerState &state_;
    std::string snapshotPath_;
    std::atomic<nuraft::ulong> lastCommitted_{0};
    std::mutex snapshotMutex_;
    nuraft::ptr<nuraft::snapshot> lastSnapshot_;
    std::string lastSnapshotData_;   // serialized state at lastSnapshot_
    std::string incoming_;           // snapshot chunks being received
};

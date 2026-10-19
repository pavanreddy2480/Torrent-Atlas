#include "tracker/raft/state_machine.hpp"

#include "tracker/raft/log_command.hpp"
#include "tracker/raft/storage_io.hpp"

using namespace nuraft;
using namespace storage_io;

namespace {
constexpr std::size_t SNAPSHOT_CHUNK = 1024 * 1024;
}

TrackerStateMachine::TrackerStateMachine(TrackerState &state, std::string snapshotPath)
    : state_(state), snapshotPath_(std::move(snapshotPath)) {
    loadSavedSnapshot();
}

// snapshot.bin: [u64 metadata length][NuRaft snapshot metadata][TrackerState text]
void TrackerStateMachine::loadSavedSnapshot() {
    std::string data;
    std::size_t position = 0;
    u64 metaLength = 0;
    if (!readFile(snapshotPath_, data) || !getU64(data, position, metaLength) ||
        data.size() < position + metaLength)
        return;
    ptr<snapshot> saved = snapshot::deserialize(*toBuffer(data.substr(position, metaLength)));
    std::string stateData = data.substr(position + metaLength);
    if (saved && state_.restore(stateData)) {
        lastSnapshot_ = saved;
        lastSnapshotData_ = std::move(stateData);
        lastCommitted_ = saved->get_last_log_idx();
    }
}

void TrackerStateMachine::saveSnapshotLocked() {
    std::string meta = toString(*lastSnapshot_->serialize());
    std::string data;
    putU64(data, meta.size());
    writeFileAtomic(snapshotPath_, data + meta + lastSnapshotData_);
}

ptr<buffer> TrackerStateMachine::commit(const ulong logIndex, buffer &data) {
    std::optional<LogCommand> entry = LogCommand::decode(toString(data));
    std::string response = "ERR corrupt log entry\t0";
    if (entry) {
        CommandResult result = state_.apply(entry->session, entry->command, entry->context);
        response = result.response + "\t" + std::to_string(result.session);
    }
    lastCommitted_ = logIndex;
    return toBuffer(response);
}

ptr<snapshot> TrackerStateMachine::last_snapshot() {
    std::lock_guard<std::mutex> lock(snapshotMutex_);
    return lastSnapshot_;
}

void TrackerStateMachine::create_snapshot(snapshot &snapshot,
                                          async_result<bool>::handler_type &whenDone) {
    {
        // Runs on the commit thread, so the state is exactly at this index.
        std::lock_guard<std::mutex> lock(snapshotMutex_);
        lastSnapshot_ = snapshot::deserialize(*snapshot.serialize());
        lastSnapshotData_ = state_.serialize();
        saveSnapshotLocked();
    }
    bool ok = true;
    ptr<std::exception> error;
    whenDone(ok, error);
}

// Leader side of a snapshot transfer: the state in 1 MiB chunks.
int TrackerStateMachine::read_logical_snp_obj(snapshot &snapshot, void *&, ulong objectId,
                                              ptr<buffer> &dataOut, bool &isLast) {
    std::lock_guard<std::mutex> lock(snapshotMutex_);
    if (!lastSnapshot_ || lastSnapshot_->get_last_log_idx() != snapshot.get_last_log_idx()) {
        dataOut = nullptr;
        isLast = true;
        return -1;
    }
    std::size_t offset = static_cast<std::size_t>(objectId) * SNAPSHOT_CHUNK;
    dataOut = toBuffer(offset < lastSnapshotData_.size()
                           ? lastSnapshotData_.substr(offset, SNAPSHOT_CHUNK)
                           : std::string());
    isLast = offset + SNAPSHOT_CHUNK >= lastSnapshotData_.size();
    return 0;
}

// Follower side: collect the chunks; apply_snapshot installs them.
void TrackerStateMachine::save_logical_snp_obj(snapshot &, ulong &objectId, buffer &data,
                                               bool isFirst, bool) {
    std::lock_guard<std::mutex> lock(snapshotMutex_);
    if (isFirst) incoming_.clear();
    incoming_ += toString(data);
    ++objectId;
}

bool TrackerStateMachine::apply_snapshot(snapshot &snapshot) {
    std::lock_guard<std::mutex> lock(snapshotMutex_);
    if (!state_.restore(incoming_)) return false;
    lastSnapshot_ = snapshot::deserialize(*snapshot.serialize());
    lastSnapshotData_ = std::move(incoming_);
    incoming_.clear();
    lastCommitted_ = snapshot.get_last_log_idx();
    saveSnapshotLocked();
    return true;
}

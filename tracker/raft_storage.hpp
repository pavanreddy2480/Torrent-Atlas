#pragma once

// Durable storage NuRaft needs on each tracker, kept as small files in the
// node's data directory:
//   raft.log      every log entry (rewritten on truncation or compaction)
//   state.bin     current term and vote
//   config.bin    cluster membership
//   snapshot.bin  latest snapshot of the tracker state
// All whole-file writes go through a temporary file, fsync, and rename.

#include "tracker_state.hpp"

#include <libnuraft/nuraft.hxx>

#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace raft_storage {

using namespace nuraft;

inline std::string bufferString(buffer &value) {
    return std::string(reinterpret_cast<const char *>(value.data_begin()), value.size());
}

inline ptr<buffer> stringBuffer(const std::string &value) {
    ptr<buffer> result = buffer::alloc(value.size());
    if (!value.empty()) std::memcpy(result->data_begin(), value.data(), value.size());
    return result;
}

inline bool readFile(const std::string &path, std::string &contents) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    contents.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return true;
}

inline bool syncedWrite(int fd, const std::string &data) {
    std::size_t written = 0;
    while (written < data.size()) {
        ssize_t count = ::write(fd, data.data() + written, data.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return ::fsync(fd) == 0;
}

inline bool writeFileAtomic(const std::string &path, const std::string &data) {
    std::string temporary = path + ".tmp";
    int fd = ::open(temporary.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return false;
    bool ok = syncedWrite(fd, data);
    ::close(fd);
    return ok && std::rename(temporary.c_str(), path.c_str()) == 0;
}

inline void putU64(std::string &out, u64 value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<char>((value >> shift) & 0xffU));
}

inline bool getU64(const std::string &in, std::size_t &pos, u64 &value) {
    if (in.size() < pos + 8) return false;
    value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | static_cast<unsigned char>(in[pos + i]);
    pos += 8;
    return true;
}

// Log store: an in-memory map backed by an append-only file.
// File: [u64 start index] then records [u64 index][u64 length][entry bytes].
class FileLogStore : public log_store {
    std::string path_;
    mutable std::mutex mutex_;
    std::map<ulong, ptr<log_entry>> logs_;
    ulong start_ = 1;

    static ptr<log_entry> dummy() { return cs_new<log_entry>(0, buffer::alloc(sz_ulong)); }

    static std::string record(ulong index, const ptr<log_entry> &entry) {
        ptr<buffer> bytes = entry->serialize();
        std::string out;
        putU64(out, index);
        putU64(out, bytes->size());
        out += bufferString(*bytes);
        return out;
    }

    // Caller holds mutex_.
    bool rewriteLocked() {
        std::string data;
        putU64(data, start_);
        for (const auto &entry : logs_) data += record(entry.first, entry.second);
        return writeFileAtomic(path_, data);
    }

    bool appendRecordLocked(ulong index, const ptr<log_entry> &entry) {
        int fd = ::open(path_.c_str(), O_WRONLY | O_APPEND);
        if (fd < 0) return false;
        bool ok = syncedWrite(fd, record(index, entry));
        ::close(fd);
        return ok;
    }

    ulong nextSlotLocked() const { return start_ + logs_.size(); }

public:
    explicit FileLogStore(std::string path) : path_(std::move(path)) {
        std::string data;
        std::size_t pos = 0;
        u64 start = 0;
        if (readFile(path_, data) && getU64(data, pos, start)) {
            start_ = start;
            for (;;) {
                u64 index = 0, length = 0;
                if (!getU64(data, pos, index) || !getU64(data, pos, length) ||
                    data.size() < pos + length)
                    break;  // a torn final record is ignored
                ptr<buffer> bytes = stringBuffer(data.substr(pos, length));
                pos += length;
                logs_.erase(logs_.lower_bound(index), logs_.end());
                logs_[index] = log_entry::deserialize(*bytes);
            }
        }
        std::lock_guard<std::mutex> lock(mutex_);
        rewriteLocked();
    }

    ulong next_slot() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return nextSlotLocked();
    }

    ulong start_index() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return start_;
    }

    ptr<log_entry> last_entry() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (logs_.empty()) return dummy();
        return logs_.rbegin()->second;
    }

    ulong append(ptr<log_entry> &entry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        ulong index = nextSlotLocked();
        logs_[index] = entry;
        appendRecordLocked(index, entry);
        return index;
    }

    void write_at(ulong index, ptr<log_entry> &entry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        logs_.erase(logs_.lower_bound(index), logs_.end());
        logs_[index] = entry;
        rewriteLocked();
    }

    ptr<std::vector<ptr<log_entry>>> log_entries(ulong start, ulong end) override {
        auto result = cs_new<std::vector<ptr<log_entry>>>();
        std::lock_guard<std::mutex> lock(mutex_);
        for (ulong index = start; index < end; ++index) {
            auto it = logs_.find(index);
            result->push_back(it == logs_.end() ? dummy() : it->second);
        }
        return result;
    }

    ptr<log_entry> entry_at(ulong index) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = logs_.find(index);
        return it == logs_.end() ? dummy() : it->second;
    }

    ulong term_at(ulong index) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = logs_.find(index);
        return it == logs_.end() ? 0 : it->second->get_term();
    }

    ptr<buffer> pack(ulong index, int32 count) override {
        std::string out;
        std::lock_guard<std::mutex> lock(mutex_);
        putU64(out, static_cast<u64>(count));
        for (ulong i = index; i < index + static_cast<ulong>(count); ++i) {
            auto it = logs_.find(i);
            ptr<buffer> bytes = (it == logs_.end() ? dummy() : it->second)->serialize();
            putU64(out, bytes->size());
            out += bufferString(*bytes);
        }
        return stringBuffer(out);
    }

    void apply_pack(ulong index, buffer &packed) override {
        std::string data = bufferString(packed);
        std::size_t pos = 0;
        u64 count = 0;
        if (!getU64(data, pos, count)) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (u64 i = 0; i < count; ++i) {
            u64 length = 0;
            if (!getU64(data, pos, length) || data.size() < pos + length) break;
            ptr<buffer> bytes = stringBuffer(data.substr(pos, length));
            pos += length;
            logs_[index + i] = log_entry::deserialize(*bytes);
        }
        if (!logs_.empty() && logs_.begin()->first > start_) start_ = logs_.begin()->first;
        rewriteLocked();
    }

    bool compact(ulong lastLogIndex) override {
        std::lock_guard<std::mutex> lock(mutex_);
        logs_.erase(logs_.begin(), logs_.upper_bound(lastLogIndex));
        if (start_ <= lastLogIndex) start_ = lastLogIndex + 1;
        return rewriteLocked();
    }

    bool flush() override { return true; }  // every write is already fsynced
};

// Term, vote and membership.
class FileStateManager : public state_mgr {
    int id_;
    std::string dir_;
    ptr<cluster_config> initialConfig_;
    ptr<FileLogStore> logStore_;

public:
    FileStateManager(int id, std::string dir, ptr<cluster_config> initialConfig)
        : id_(id), dir_(std::move(dir)), initialConfig_(std::move(initialConfig)),
          logStore_(cs_new<FileLogStore>(dir_ + "/raft.log")) {}

    ptr<cluster_config> load_config() override {
        std::string data;
        if (!readFile(dir_ + "/config.bin", data) || data.empty()) return initialConfig_;
        ptr<buffer> bytes = stringBuffer(data);
        return cluster_config::deserialize(*bytes);
    }

    void save_config(const cluster_config &config) override {
        writeFileAtomic(dir_ + "/config.bin", bufferString(*config.serialize()));
    }

    void save_state(const srv_state &state) override {
        writeFileAtomic(dir_ + "/state.bin", bufferString(*state.serialize()));
    }

    ptr<srv_state> read_state() override {
        std::string data;
        if (!readFile(dir_ + "/state.bin", data) || data.empty()) return nullptr;
        ptr<buffer> bytes = stringBuffer(data);
        return srv_state::deserialize(*bytes);
    }

    ptr<log_store> load_log_store() override { return logStore_; }
    int32 server_id() override { return id_; }
    void system_exit(const int exitCode) override { std::_Exit(exitCode); }
};

}  // namespace raft_storage

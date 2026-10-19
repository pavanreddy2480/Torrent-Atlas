#include "tracker/raft/raft_storage.hpp"

#include "tracker/raft/storage_io.hpp"

using namespace nuraft;
using namespace storage_io;

namespace {

ptr<log_entry> dummyEntry() { return cs_new<log_entry>(0, buffer::alloc(sz_ulong)); }

std::string record(ulong index, const ptr<log_entry> &entry) {
    std::string bytes = toString(*entry->serialize());
    std::string out;
    putU64(out, index);
    putU64(out, bytes.size());
    return out + bytes;
}

}  // namespace

FileLogStore::FileLogStore(std::string path) : path_(std::move(path)) {
    std::string data;
    std::size_t position = 0;
    u64 start = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    if (readFile(path_, data) && getU64(data, position, start)) {
        start_ = start;
        for (;;) {
            u64 index = 0, length = 0;
            if (!getU64(data, position, index) || !getU64(data, position, length) ||
                data.size() < position + length)
                break;   // a torn final record is ignored
            ptr<buffer> bytes = toBuffer(data.substr(position, length));
            position += length;
            entries_.erase(entries_.lower_bound(index), entries_.end());
            entries_[index] = log_entry::deserialize(*bytes);
        }
    }
    rewrite();
}

ptr<log_entry> FileLogStore::entryOrDummy(ulong index) const {
    auto entry = entries_.find(index);
    return entry == entries_.end() ? dummyEntry() : entry->second;
}

bool FileLogStore::rewrite() {
    std::string data;
    putU64(data, start_);
    for (const auto &entry : entries_) data += record(entry.first, entry.second);
    return writeFileAtomic(path_, data);
}

ulong FileLogStore::next_slot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return start_ + entries_.size();
}

ulong FileLogStore::start_index() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return start_;
}

ptr<log_entry> FileLogStore::last_entry() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty() ? dummyEntry() : entries_.rbegin()->second;
}

ulong FileLogStore::append(ptr<log_entry> &entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    ulong index = start_ + entries_.size();
    entries_[index] = entry;
    appendFileSynced(path_, record(index, entry));
    return index;
}

void FileLogStore::write_at(ulong index, ptr<log_entry> &entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(entries_.lower_bound(index), entries_.end());
    entries_[index] = entry;
    rewrite();
}

ptr<std::vector<ptr<log_entry>>> FileLogStore::log_entries(ulong start, ulong end) {
    auto result = cs_new<std::vector<ptr<log_entry>>>();
    std::lock_guard<std::mutex> lock(mutex_);
    for (ulong index = start; index < end; ++index) result->push_back(entryOrDummy(index));
    return result;
}

ptr<log_entry> FileLogStore::entry_at(ulong index) {
    std::lock_guard<std::mutex> lock(mutex_);
    return entryOrDummy(index);
}

ulong FileLogStore::term_at(ulong index) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto entry = entries_.find(index);
    return entry == entries_.end() ? 0 : entry->second->get_term();
}

ptr<buffer> FileLogStore::pack(ulong index, int32 count) {
    std::string out;
    putU64(out, static_cast<u64>(count));
    std::lock_guard<std::mutex> lock(mutex_);
    for (ulong i = index; i < index + static_cast<ulong>(count); ++i) {
        std::string bytes = toString(*entryOrDummy(i)->serialize());
        putU64(out, bytes.size());
        out += bytes;
    }
    return toBuffer(out);
}

void FileLogStore::apply_pack(ulong index, buffer &packed) {
    std::string data = toString(packed);
    std::size_t position = 0;
    u64 count = 0;
    if (!getU64(data, position, count)) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (u64 i = 0; i < count; ++i) {
        u64 length = 0;
        if (!getU64(data, position, length) || data.size() < position + length) break;
        ptr<buffer> bytes = toBuffer(data.substr(position, length));
        position += length;
        entries_[index + i] = log_entry::deserialize(*bytes);
    }
    if (!entries_.empty() && entries_.begin()->first > start_) start_ = entries_.begin()->first;
    rewrite();
}

bool FileLogStore::compact(ulong lastLogIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(entries_.begin(), entries_.upper_bound(lastLogIndex));
    if (start_ <= lastLogIndex) start_ = lastLogIndex + 1;
    return rewrite();
}

FileStateManager::FileStateManager(int id, std::string dir, ptr<cluster_config> initialConfig)
    : id_(id), dir_(std::move(dir)), initialConfig_(std::move(initialConfig)),
      logStore_(cs_new<FileLogStore>(dir_ + "/raft.log")) {}

ptr<cluster_config> FileStateManager::load_config() {
    std::string data;
    if (!readFile(dir_ + "/config.bin", data) || data.empty()) return initialConfig_;
    return cluster_config::deserialize(*toBuffer(data));
}

void FileStateManager::save_config(const cluster_config &config) {
    writeFileAtomic(dir_ + "/config.bin", toString(*config.serialize()));
}

void FileStateManager::save_state(const srv_state &state) {
    writeFileAtomic(dir_ + "/state.bin", toString(*state.serialize()));
}

ptr<srv_state> FileStateManager::read_state() {
    std::string data;
    if (!readFile(dir_ + "/state.bin", data) || data.empty()) return nullptr;
    return srv_state::deserialize(*toBuffer(data));
}

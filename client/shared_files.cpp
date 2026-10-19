#include "shared_files.hpp"

void SharedFiles::add(const std::string &group, const std::string &name, LocalFile file) {
    std::lock_guard<std::mutex> lock(mutex_);
    files_[{group, name}] = std::move(file);
}

std::optional<LocalFile> SharedFiles::find(const std::string &group,
                                           const std::string &name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto file = files_.find({group, name});
    if (file == files_.end()) return std::nullopt;
    return file->second;
}

void SharedFiles::markAvailable(const std::string &group, const std::string &name,
                                std::size_t piece) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto file = files_.find({group, name});
    if (file != files_.end() && piece < file->second.available.size())
        file->second.available[piece] = true;
}

void SharedFiles::remove(const std::string &group, const std::string &name) {
    std::lock_guard<std::mutex> lock(mutex_);
    files_.erase({group, name});
}

void SharedFiles::removeGroup(const std::string &group) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto file = files_.begin(); file != files_.end();)
        file = file->first.first == group ? files_.erase(file) : std::next(file);
}

void SharedFiles::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    files_.clear();
}

#pragma once

// The files this client serves to peers, keyed by (group, file name).
// Shared between the command prompt, downloads and the peer server.

#include "client/storage/local_file.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

class SharedFiles {
public:
    void add(const std::string &group, const std::string &name, LocalFile file);
    std::optional<LocalFile> find(const std::string &group, const std::string &name) const;
    void markAvailable(const std::string &group, const std::string &name, std::size_t piece);
    void remove(const std::string &group, const std::string &name);
    void removeGroup(const std::string &group);
    void clear();

private:
    using Key = std::pair<std::string, std::string>;

    mutable std::mutex mutex_;
    std::map<Key, LocalFile> files_;
};

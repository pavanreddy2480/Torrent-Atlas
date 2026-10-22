#pragma once

/// @file shared_files.hpp
/// The set of files this client serves to peers.

#include "client/storage/local_file.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

/// Files this client seeds, keyed by (group, file name).
///
/// Shared by the command prompt (uploads, stop share, leave, logout),
/// downloads (adding a file and marking pieces as they arrive) and the peer
/// server (looking files up). Thread-safe: every method takes an internal
/// lock.
class SharedFiles {
public:
    /// Adds a file, replacing any entry with the same group and name.
    void add(const std::string &group, const std::string &name, LocalFile file);

    /// @return A copy of the entry, or std::nullopt if it isn't shared.
    ///         A copy, so the caller can use it without holding the lock.
    std::optional<LocalFile> find(const std::string &group, const std::string &name) const;

    /// Marks one piece as verified and servable. Ignored if the file is not
    /// shared or piece is out of range.
    void markAvailable(const std::string &group, const std::string &name, std::size_t piece);

    /// Stops sharing one file. No-op if it isn't shared.
    void remove(const std::string &group, const std::string &name);

    /// Stops sharing every file in group.
    void removeGroup(const std::string &group);

    /// Stops sharing everything (on logout).
    void clear();

private:
    using Key = std::pair<std::string, std::string>;   ///< (group, file name)

    mutable std::mutex mutex_;   ///< Guards files_.
    std::map<Key, LocalFile> files_;
};

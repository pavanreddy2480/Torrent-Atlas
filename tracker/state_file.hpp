#pragma once

/// @file state_file.hpp
/// <data-dir>/tracker.state: where the tracker keeps its saved TrackerState.

#include <string>

/// Reads and atomically replaces one file.
///
/// write() goes to "<path>.tmp" (mode 0600), fsyncs it, then renames it over
/// path, so after a crash the file holds either the old contents or the new,
/// never a mix. Not safe for two concurrent writers; TrackerService
/// serializes its writes.
class StateFile {
public:
    explicit StateFile(std::string path) : path_(std::move(path)) {}

    /// Reads the whole file.
    /// @param contents Receives the bytes.
    /// @return false if the file does not exist or cannot be read.
    bool read(std::string &contents) const;

    /// Replaces the file with contents, durably.
    /// @return false if writing, syncing or renaming failed; the old file is
    ///         then still intact.
    bool write(const std::string &contents) const;

    /// @return The file's path.
    const std::string &path() const { return path_; }

private:
    std::string path_;
};

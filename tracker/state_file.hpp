#pragma once

// <data-dir>/tracker.state: the tracker's saved TrackerState. Each save
// writes a temporary file, fsyncs it and renames it over the old one, so a
// crash leaves either the old state or the new one. Mode 0600.

#include <string>

class StateFile {
public:
    explicit StateFile(std::string path) : path_(std::move(path)) {}

    // False if the file does not exist or cannot be read.
    bool read(std::string &contents) const;
    bool write(const std::string &contents) const;

    const std::string &path() const { return path_; }

private:
    std::string path_;
};

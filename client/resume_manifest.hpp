#pragma once

// <destination>.resume records which pieces of <destination>.part are already
// verified, so an interrupted download can continue where it stopped. It is
// tied to one file: a manifest for different metadata is ignored.

#include "../common/file_metadata.hpp"

#include <optional>
#include <string>
#include <vector>

class ResumeManifest {
public:
    ResumeManifest(std::string path, std::string group, std::string name, FileMetadata metadata,
                   std::string partPath);

    // The verified-piece list from an existing manifest for this same file.
    std::optional<std::vector<bool>> load() const;
    bool save(const std::vector<bool> &verified) const;
    void remove() const;

private:
    std::string path_;
    std::string group_;
    std::string name_;
    FileMetadata metadata_;
    std::string partPath_;
};

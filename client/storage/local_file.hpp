#pragma once

#include "common/file_metadata.hpp"

#include <string>
#include <vector>

// A file this client can serve to peers: complete, or a download in progress.
struct LocalFile {
    std::string path;
    FileMetadata metadata;
    std::vector<bool> available;   // pieces on disk and verified
};

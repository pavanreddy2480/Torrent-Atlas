#pragma once

/// @file local_file.hpp
/// A file this client can serve to peers.

#include "common/file_metadata.hpp"

#include <string>
#include <vector>

/// A complete file, or a download in progress, that the peer server may
/// read pieces from. A plain value type.
struct LocalFile {
    std::string path;              ///< Where the bytes are (the .part file while downloading).
    FileMetadata metadata;         ///< Size and hashes, from the tracker.
    std::vector<bool> available;   ///< available[i]: piece i is on disk and verified.
};

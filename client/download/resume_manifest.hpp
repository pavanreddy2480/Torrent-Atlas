#pragma once

/// @file resume_manifest.hpp
/// <destination>.resume: which pieces of <destination>.part are already
/// verified, so an interrupted download can continue where it stopped.
///
/// Format (8 lines): "P2PRESUME2", hex group, hex name, size, SHA-1, piece
/// hashes, a '0'/'1' per piece, hex .part path. Holds no keys. Mode 0600.

#include "common/file_metadata.hpp"

#include <optional>
#include <string>
#include <vector>

/// The resume manifest for one download. Tied to one exact file: a
/// manifest written for a different group, name, metadata or .part path is
/// ignored. Not thread-safe; Download serializes access.
class ResumeManifest {
public:
    /// @param path     Where the manifest lives ("<destination>.resume").
    /// @param partPath The .part file it describes.
    ResumeManifest(std::string path, std::string group, std::string name, FileMetadata metadata,
                   std::string partPath);

    /// Reads an existing manifest for this same file.
    /// @return One flag per piece (true = verified earlier), or std::nullopt
    ///         if there is no manifest or it belongs to something else or is
    ///         malformed. The caller must still re-hash the claimed pieces.
    std::optional<std::vector<bool>> load() const;

    /// Saves the verified flags. Writes "<path>.tmp" then renames it, so a
    /// crash never leaves a half-written manifest.
    /// @param verified One flag per piece.
    /// @return false if the file could not be written.
    bool save(const std::vector<bool> &verified) const;

    /// Deletes the manifest (after the download completes). No-op if absent.
    void remove() const;

private:
    std::string path_;
    std::string group_;
    std::string name_;
    FileMetadata metadata_;
    std::string partPath_;
};

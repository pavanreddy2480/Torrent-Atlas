#pragma once

/// @file piece_file.hpp
/// A file on disk read and written one 512 KiB piece at a time.

#include "common/file_metadata.hpp"

#include <string>

/// RAII owner of one open file, addressed by piece number.
///
/// Uses pread/pwrite at explicit offsets on a single descriptor, so several
/// download threads may read and write *different* pieces of the same
/// PieceFile at once without locking. Move-only; closes the file on
/// destruction. A default-constructed or failed PieceFile converts to false.
class PieceFile {
public:
    PieceFile() = default;
    ~PieceFile();
    PieceFile(PieceFile &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    /// Closes the current file, then takes other's.
    PieceFile &operator=(PieceFile &&other) noexcept;
    PieceFile(const PieceFile &) = delete;
    PieceFile &operator=(const PieceFile &) = delete;

    /// Opens an existing file read-only.
    /// @return The file, or an invalid PieceFile if it can't be opened.
    static PieceFile openForReading(const std::string &path);

    /// Opens (creating with mode 0600 if needed) a file for reading and
    /// writing and sets its length to size, so every piece has a place.
    /// @param keepContents true to keep existing bytes (resuming); false to
    ///                     empty the file first.
    /// @return The file, or an invalid PieceFile on failure.
    static PieceFile openForWriting(const std::string &path, u64 size, bool keepContents);

    /// @return true if a file is open.
    explicit operator bool() const { return fd_ >= 0; }

    /// Reads one piece.
    /// @param index  Piece number; the read starts at index * PIECE_SIZE.
    /// @param length Bytes to read (FileMetadata::pieceLength(index)).
    /// @param data   Receives exactly length bytes.
    /// @return false if the file ends early or the read fails.
    bool read(std::size_t index, std::size_t length, std::string &data) const;

    /// Writes one piece at index * PIECE_SIZE. Not durable until sync().
    /// @return false if the write fails.
    bool write(std::size_t index, const std::string &data) const;

    /// Flushes written data to the disk (fsync).
    /// @return false if the flush fails.
    bool sync() const;

    /// Reads a whole file and computes its metadata.
    /// @param path     A regular file.
    /// @param metadata Receives size, fullHash and pieceHashes.
    /// @return false if path is not a readable regular file.
    static bool hash(const std::string &path, FileMetadata &metadata);

private:
    explicit PieceFile(int fd) : fd_(fd) {}

    int fd_ = -1;
};

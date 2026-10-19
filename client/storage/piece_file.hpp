#pragma once

// A file on disk read and written one piece at a time. Several download
// threads write different pieces of the same file at once, so this uses
// pread/pwrite on one descriptor.

#include "common/file_metadata.hpp"

#include <string>

class PieceFile {
public:
    PieceFile() = default;
    ~PieceFile();
    PieceFile(PieceFile &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    PieceFile &operator=(PieceFile &&other) noexcept;
    PieceFile(const PieceFile &) = delete;
    PieceFile &operator=(const PieceFile &) = delete;

    static PieceFile openForReading(const std::string &path);
    // Creates the file if needed and sets its size; keepContents=false empties it first.
    static PieceFile openForWriting(const std::string &path, u64 size, bool keepContents);

    explicit operator bool() const { return fd_ >= 0; }
    bool read(std::size_t index, std::size_t length, std::string &data) const;
    bool write(std::size_t index, const std::string &data) const;
    bool sync() const;

    // Fills in size, fullHash and pieceHashes from the file's contents.
    static bool hash(const std::string &path, FileMetadata &metadata);

private:
    explicit PieceFile(int fd) : fd_(fd) {}

    int fd_ = -1;
};

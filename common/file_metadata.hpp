#pragma once

// What the tracker stores about a shared file and what a downloader needs:
// its size, SHA-1 of the whole file and of every 512 KiB piece, and the
// capability, a random 256-bit key that peers use to encrypt piece traffic.

#include "common/encoding.hpp"

#include <string>
#include <vector>

constexpr std::size_t PIECE_SIZE = 512U * 1024U;

inline u64 pieceCountForSize(u64 size) { return size / PIECE_SIZE + (size % PIECE_SIZE != 0); }

struct FileMetadata {
    u64 size = 0;
    std::string fullHash;      // hex SHA-1
    std::string capability;    // 64 hex digits
    std::vector<std::string> pieceHashes;

    std::size_t pieceCount() const { return pieceHashes.size(); }
    std::size_t pieceLength(std::size_t index) const;

    // Hashes are SHA-1 hex, the capability is 64 hex digits, and the piece
    // count matches the size.
    bool valid() const;

    // Comma-separated piece hashes, or "-" for an empty file.
    std::string pieceHashList() const;
    static std::vector<std::string> parsePieceHashList(const std::string &text);

    bool sameContent(const FileMetadata &other) const {
        return size == other.size && fullHash == other.fullHash && pieceHashes == other.pieceHashes;
    }
};

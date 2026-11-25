#pragma once

/// @file file_metadata.hpp
/// What the tracker stores about a shared file and what a downloader needs
/// to fetch and verify it: its size and the SHA-256 of the whole file and of
/// every 2 MiB piece.

#include "common/encoding.hpp"

#include <string>
#include <vector>

/// Every file is cut into pieces of this size; the last may be shorter.
///
/// 2 MiB, from the ablation study (docs/ablations/RESULTS.md): each piece costs
/// one request round trip, so bigger pieces pay network latency less often
/// (143 MB/s at 4 MiB vs 99 MB/s at 512 KiB with 5 ms latency). A corrupt piece
/// costs more to refetch, which is the trade-off.
constexpr std::size_t PIECE_SIZE = 2U * 1024U * 1024U;

/// @return How many pieces a file of `size` bytes has (0 for an empty file).
inline u64 pieceCountForSize(u64 size) { return size / PIECE_SIZE + (size % PIECE_SIZE != 0); }

/// A file's identity and integrity data. A plain value type.
struct FileMetadata {
    u64 size = 0;                          ///< Bytes in the whole file.
    std::string fullHash;                  ///< SHA-256 of the whole file, 64 hex digits.
    std::vector<std::string> pieceHashes;  ///< SHA-256 of each piece, in order.

    /// @return The number of pieces (== pieceHashes.size()).
    std::size_t pieceCount() const { return pieceHashes.size(); }

    /// @param index A piece number, 0 <= index < pieceCount().
    /// @return Its length: PIECE_SIZE, or less for the last piece.
    std::size_t pieceLength(std::size_t index) const;

    /// Checks data received from the network or disk before it is trusted.
    /// @return true if every hash is 64 hex digits and the number of piece
    ///         hashes matches the size.
    bool valid() const;

    /// @return The piece hashes joined with ',', or "-" for an empty file
    ///         (so the field is never empty on the wire).
    std::string pieceHashList() const;

    /// The inverse of pieceHashList(). Does not validate; call valid().
    static std::vector<std::string> parsePieceHashList(const std::string &text);

    /// @return true if other describes the same bytes (size and all hashes).
    bool sameContent(const FileMetadata &other) const {
        return size == other.size && fullHash == other.fullHash && pieceHashes == other.pieceHashes;
    }
};

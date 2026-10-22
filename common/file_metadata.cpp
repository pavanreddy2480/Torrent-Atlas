#include "common/file_metadata.hpp"

#include <algorithm>

std::size_t FileMetadata::pieceLength(std::size_t index) const {
    return static_cast<std::size_t>(
        std::min<u64>(PIECE_SIZE, size - static_cast<u64>(index) * PIECE_SIZE));
}

bool FileMetadata::valid() const {
    return isSha1Hex(fullHash) &&
           pieceHashes.size() == pieceCountForSize(size) &&
           std::all_of(pieceHashes.begin(), pieceHashes.end(), isSha1Hex);
}

std::string FileMetadata::pieceHashList() const {
    return pieceHashes.empty() ? "-" : join(pieceHashes, ',');
}

std::vector<std::string> FileMetadata::parsePieceHashList(const std::string &text) {
    return text == "-" ? std::vector<std::string>{} : split(text, ',');
}

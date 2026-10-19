#include "client/download/resume_manifest.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace {
const std::string VERSION = "P2PRESUME1";
}

ResumeManifest::ResumeManifest(std::string path, std::string group, std::string name,
                               FileMetadata metadata, std::string partPath)
    : path_(std::move(path)), group_(std::move(group)), name_(std::move(name)),
      metadata_(std::move(metadata)), partPath_(std::move(partPath)) {}

// Nine lines: version, hex group, hex name, size, SHA-1, capability, piece
// hashes, a 0/1 per piece, hex .part path.
bool ResumeManifest::save(const std::vector<bool> &verified) const {
    std::string bitmap;
    for (bool piece : verified) bitmap.push_back(piece ? '1' : '0');
    std::string temporary = path_ + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        output << VERSION << '\n'
               << toHex(group_) << '\n'
               << toHex(name_) << '\n'
               << metadata_.size << '\n'
               << metadata_.fullHash << '\n'
               << metadata_.capability << '\n'
               << metadata_.pieceHashList() << '\n'
               << bitmap << '\n'
               << toHex(partPath_) << '\n';
        if (!output.flush()) return false;
    }
    std::error_code error;
    fs::permissions(temporary, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, error);
    fs::rename(temporary, path_, error);
    return !error;
}

std::optional<std::vector<bool>> ResumeManifest::load() const {
    std::ifstream input(path_);
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);) lines.push_back(line);
    std::string expectedSize = std::to_string(metadata_.size);
    if (lines.size() != 9 || lines[0] != VERSION || lines[1] != toHex(group_) ||
        lines[2] != toHex(name_) || lines[3] != expectedSize || lines[4] != metadata_.fullHash ||
        lines[5] != metadata_.capability || lines[6] != metadata_.pieceHashList() ||
        lines[7].size() != metadata_.pieceCount() || lines[8] != toHex(partPath_))
        return std::nullopt;
    std::vector<bool> verified;
    for (char piece : lines[7]) {
        if (piece != '0' && piece != '1') return std::nullopt;
        verified.push_back(piece == '1');
    }
    return verified;
}

void ResumeManifest::remove() const { std::remove(path_.c_str()); }

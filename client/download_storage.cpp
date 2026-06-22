#include "download_storage.hpp"

#include "../common/protocol.hpp"
#include "../common/sha1.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

bool saveResumeLocked(const ResumeState &resume) {
    std::string temporaryManifest = resume.manifestPath + ".tmp";
    std::ofstream output(temporaryManifest, std::ios::trunc);
    if (!output) return false;
    output << "P2PRESUME1\n"
           << hexEncode(resume.group) << '\n'
           << hexEncode(resume.name) << '\n'
           << resume.metadata.size << '\n'
           << resume.metadata.fullHash << '\n'
           << resume.metadata.capability << '\n'
           << joinHashes(resume.metadata.pieceHashes) << '\n';
    for (unsigned char piece : resume.verified)
        output << (piece ? '1' : '0');
    output << '\n' << hexEncode(resume.temporaryPath) << '\n';
    output.flush();
    if (!output) return false;
    output.close();
    chmod(temporaryManifest.c_str(), 0600);
    if (rename(temporaryManifest.c_str(), resume.manifestPath.c_str()) != 0)
        return false;
    chmod(resume.manifestPath.c_str(), 0600);
    return true;
}

bool loadResume(const std::string &manifestPath, const std::string &group,
                const std::string &name, const LocalFile &metadata,
                std::string &temporaryPath,
                std::vector<unsigned char> &verified) {
    std::ifstream input(manifestPath);
    std::string version;
    std::string encodedGroup;
    std::string encodedName;
    std::string sizeText;
    std::string fullHash;
    std::string capability;
    std::string hashes;
    std::string bitmap;
    std::string encodedTemporary;
    if (!std::getline(input, version) ||
        !std::getline(input, encodedGroup) ||
        !std::getline(input, encodedName) ||
        !std::getline(input, sizeText) ||
        !std::getline(input, fullHash) ||
        !std::getline(input, capability) ||
        !std::getline(input, hashes) ||
        !std::getline(input, bitmap) ||
        !std::getline(input, encodedTemporary) || version != "P2PRESUME1")
        return false;
    std::string storedGroup;
    std::string storedName;
    u64 storedSize = 0;
    try {
        storedSize = static_cast<u64>(std::stoull(sizeText));
    } catch (...) {
        return false;
    }
    if (!hexDecode(encodedGroup, storedGroup) ||
        !hexDecode(encodedName, storedName) ||
        !hexDecode(encodedTemporary, temporaryPath) ||
        storedGroup != group || storedName != name ||
        storedSize != metadata.size || fullHash != metadata.fullHash ||
        capability != metadata.capability ||
        hashes != joinHashes(metadata.pieceHashes) ||
        bitmap.size() != metadata.pieceHashes.size())
        return false;
    verified.resize(bitmap.size());
    for (std::size_t index = 0; index < bitmap.size(); ++index) {
        if (bitmap[index] != '0' && bitmap[index] != '1') return false;
        verified[index] = bitmap[index] == '1';
    }
    return true;
}

bool verifyStoredPieces(int descriptor, const LocalFile &metadata,
                        std::vector<unsigned char> &verified) {
    std::vector<char> buffer(PIECE_SIZE);
    for (std::size_t piece = 0; piece < verified.size(); ++piece) {
        if (!verified[piece]) continue;
        std::size_t expected = static_cast<std::size_t>(
            std::min<u64>(PIECE_SIZE,
                          metadata.size -
                              static_cast<u64>(piece) * PIECE_SIZE));
        std::size_t received = 0;
        off_t offset = static_cast<off_t>(piece * PIECE_SIZE);
        while (received < expected) {
            ssize_t count =
                pread(descriptor, buffer.data() + received,
                      expected - received,
                      offset + static_cast<off_t>(received));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            received += static_cast<std::size_t>(count);
        }
        Sha1 hash;
        hash.update(buffer.data(), received);
        if (received != expected ||
            hash.finalHex() != metadata.pieceHashes[piece])
            verified[piece] = 0;
    }
    return true;
}

bool hashFile(const std::string &path, u64 &size, std::string &fullHash,
              std::vector<std::string> &pieceHashes) {
    int descriptor = open(path.c_str(), O_RDONLY);
    if (descriptor < 0) return false;
    Sha1 complete;
    std::vector<char> buffer(PIECE_SIZE);
    size = 0;
    pieceHashes.clear();
    for (;;) {
        std::size_t used = 0;
        while (used < buffer.size()) {
            ssize_t count =
                read(descriptor, buffer.data() + used, buffer.size() - used);
            if (count < 0) {
                if (errno == EINTR) continue;
                close(descriptor);
                return false;
            }
            if (count == 0) break;
            used += static_cast<std::size_t>(count);
        }
        if (used == 0) break;
        Sha1 piece;
        piece.update(buffer.data(), used);
        pieceHashes.push_back(piece.finalHex());
        complete.update(buffer.data(), used);
        size += used;
        if (used < buffer.size()) break;
    }
    close(descriptor);
    fullHash = complete.finalHex();
    return true;
}

std::string joinHashes(const std::vector<std::string> &hashes) {
    if (hashes.empty()) return "-";
    std::string result;
    for (std::size_t index = 0; index < hashes.size(); ++index) {
        if (index) result.push_back(',');
        result += hashes[index];
    }
    return result;
}

bool writePiece(int descriptor, std::size_t index,
                const std::string &piece) {
    std::size_t written = 0;
    off_t offset = static_cast<off_t>(index * PIECE_SIZE);
    while (written < piece.size()) {
        ssize_t count =
            pwrite(descriptor, piece.data() + written,
                   piece.size() - written,
                   offset + static_cast<off_t>(written));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return true;
}

std::string baseName(const std::string &path) {
    std::size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string resolvedDestination(const std::string &destination,
                                const std::string &name) {
    struct stat info {};
    if (stat(destination.c_str(), &info) == 0 && S_ISDIR(info.st_mode))
        return destination + (destination.back() == '/' ? "" : "/") +
               name;
    return destination;
}

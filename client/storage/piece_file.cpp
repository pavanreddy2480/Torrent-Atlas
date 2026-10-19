#include "client/storage/piece_file.hpp"

#include "common/crypto/crypto.hpp"

#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace {

off_t pieceOffset(std::size_t index) { return static_cast<off_t>(index) * PIECE_SIZE; }

}  // namespace

PieceFile::~PieceFile() {
    if (fd_ >= 0) ::close(fd_);
}

PieceFile &PieceFile::operator=(PieceFile &&other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

PieceFile PieceFile::openForReading(const std::string &path) {
    return PieceFile(::open(path.c_str(), O_RDONLY));
}

PieceFile PieceFile::openForWriting(const std::string &path, u64 size, bool keepContents) {
    PieceFile file(::open(path.c_str(), O_CREAT | O_RDWR | (keepContents ? 0 : O_TRUNC), 0600));
    if (file && ::ftruncate(file.fd_, static_cast<off_t>(size)) != 0) return PieceFile();
    return file;
}

bool PieceFile::read(std::size_t index, std::size_t length, std::string &data) const {
    data.assign(length, '\0');
    std::size_t done = 0;
    while (done < length) {
        ssize_t count = ::pread(fd_, &data[done], length - done,
                                pieceOffset(index) + static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += static_cast<std::size_t>(count);
    }
    return true;
}

bool PieceFile::write(std::size_t index, const std::string &data) const {
    std::size_t done = 0;
    while (done < data.size()) {
        ssize_t count = ::pwrite(fd_, data.data() + done, data.size() - done,
                                 pieceOffset(index) + static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        done += static_cast<std::size_t>(count);
    }
    return true;
}

bool PieceFile::sync() const { return ::fsync(fd_) == 0; }

bool PieceFile::hash(const std::string &path, FileMetadata &metadata) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error)) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    crypto::Sha1 whole;
    std::string buffer(PIECE_SIZE, '\0');
    metadata.size = 0;
    metadata.pieceHashes.clear();
    while (input.read(&buffer[0], static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
        std::size_t length = static_cast<std::size_t>(input.gcount());
        metadata.pieceHashes.push_back(crypto::sha1Hex(buffer.substr(0, length)));
        whole.update(buffer.data(), length);
        metadata.size += length;
    }
    if (input.bad()) return false;
    metadata.fullHash = whole.hexDigest();
    return true;
}

#include "tracker/raft/storage_io.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <unistd.h>

namespace storage_io {

namespace {

bool writeSynced(const std::string &path, int flags, const std::string &contents) {
    int fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0) return false;
    std::size_t written = 0;
    bool ok = true;
    while (ok && written < contents.size()) {
        ssize_t count = ::write(fd, contents.data() + written, contents.size() - written);
        if (count < 0 && errno == EINTR) continue;
        ok = count > 0;
        if (ok) written += static_cast<std::size_t>(count);
    }
    ok = ok && ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

}  // namespace

std::string toString(nuraft::buffer &buffer) {
    return std::string(reinterpret_cast<const char *>(buffer.data_begin()), buffer.size());
}

nuraft::ptr<nuraft::buffer> toBuffer(const std::string &bytes) {
    nuraft::ptr<nuraft::buffer> buffer = nuraft::buffer::alloc(bytes.size());
    if (!bytes.empty()) std::memcpy(buffer->data_begin(), bytes.data(), bytes.size());
    return buffer;
}

bool readFile(const std::string &path, std::string &contents) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    contents.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return true;
}

bool writeFileAtomic(const std::string &path, const std::string &contents) {
    std::string temporary = path + ".tmp";
    return writeSynced(temporary, O_CREAT | O_WRONLY | O_TRUNC, contents) &&
           std::rename(temporary.c_str(), path.c_str()) == 0;
}

bool appendFileSynced(const std::string &path, const std::string &contents) {
    return writeSynced(path, O_WRONLY | O_APPEND, contents);
}

void putU64(std::string &out, u64 value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<char>((value >> shift) & 0xffU));
}

bool getU64(const std::string &in, std::size_t &position, u64 &value) {
    if (in.size() < position + 8) return false;
    value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | static_cast<unsigned char>(in[position + i]);
    position += 8;
    return true;
}

}  // namespace storage_io

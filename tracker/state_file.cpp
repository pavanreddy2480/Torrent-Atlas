#include "tracker/state_file.hpp"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <unistd.h>

bool StateFile::read(std::string &contents) const {
    std::ifstream input(path_, std::ios::binary);
    if (!input) return false;
    contents.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return !input.bad();
}

bool StateFile::write(const std::string &contents) const {
    std::string temporary = path_ + ".tmp";
    int fd = ::open(temporary.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return false;
    std::size_t written = 0;
    bool ok = true;
    while (ok && written < contents.size()) {
        ssize_t count = ::write(fd, contents.data() + written, contents.size() - written);
        if (count < 0 && errno == EINTR) continue;
        ok = count > 0;
        if (ok) written += static_cast<std::size_t>(count);
    }
    ok = ::fsync(fd) == 0 && ok;
    ::close(fd);
    return ok && std::rename(temporary.c_str(), path_.c_str()) == 0;
}

#include "../client/download_storage.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

int main() {
    std::string prefix = "/tmp/torrent-resume-test-" +
                         std::to_string(getpid());
    ResumeState resume;
    resume.manifestPath = prefix + ".resume";
    resume.temporaryPath = prefix + ".part";
    resume.group = "group";
    resume.name = "file";
    resume.metadata.size = 1;
    resume.metadata.fullHash = "0123456789abcdef0123456789abcdef01234567";
    resume.metadata.capability =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    resume.metadata.pieceHashes = {
        "89abcdef0123456789abcdef0123456789abcdef"};
    resume.verified = {1};
    assert(saveResumeLocked(resume));

    std::string temporary;
    std::vector<unsigned char> verified;
    assert(loadResume(resume.manifestPath, resume.group, resume.name,
                      resume.metadata, temporary, verified));
    assert(temporary == resume.temporaryPath && verified == resume.verified);

    {
        std::ofstream output(resume.manifestPath, std::ios::app);
        output << "unexpected\n";
    }
    assert(!loadResume(resume.manifestPath, resume.group, resume.name,
                       resume.metadata, temporary, verified));

    auto checkFile = [&](std::size_t size, std::size_t expectedPieces) {
        std::string path = prefix + "-" + std::to_string(size) + ".bin";
        {
            std::ofstream output(path, std::ios::binary);
            std::string block(8192, 'x');
            std::size_t remaining = size;
            while (remaining != 0) {
                std::size_t amount = std::min(remaining, block.size());
                output.write(block.data(), static_cast<std::streamsize>(amount));
                remaining -= amount;
            }
        }
        u64 hashedSize = 0;
        std::string fullHash;
        std::vector<std::string> pieceHashes;
        assert(hashFile(path, hashedSize, fullHash, pieceHashes));
        assert(hashedSize == size && pieceHashes.size() == expectedPieces);
        assert(isSha1Hex(fullHash));
        unlink(path.c_str());
    };
    checkFile(0, 0);
    checkFile(17, 1);
    checkFile(PIECE_SIZE, 1);
    checkFile(PIECE_SIZE + 17, 2);

    unlink(resume.manifestPath.c_str());
    std::cout << "download storage tests passed\n";
}

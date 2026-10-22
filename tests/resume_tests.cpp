/// @file resume_tests.cpp
/// Resume manifests (saving, loading, rejecting mismatches), file hashing,
/// and piece reads and writes.
#include "client/storage/piece_file.hpp"
#include "client/download/resume_manifest.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <unistd.h>

int main() {
    std::string prefix = "/tmp/torrent-resume-test-" + std::to_string(getpid());
    FileMetadata metadata;
    metadata.size = 1;
    metadata.fullHash = "0123456789abcdef0123456789abcdef01234567";
    metadata.pieceHashes = {"89abcdef0123456789abcdef0123456789abcdef"};

    ResumeManifest manifest(prefix + ".resume", "group", "file", metadata, prefix + ".part");
    assert(manifest.save({true}));
    assert(manifest.load() == std::vector<bool>{true});

    // A manifest for other metadata or another .part path is ignored.
    FileMetadata changed = metadata;
    changed.size = 2;
    assert(!ResumeManifest(prefix + ".resume", "group", "file", changed, prefix + ".part").load());
    assert(!ResumeManifest(prefix + ".resume", "group", "file", metadata, prefix + ".other").load());

    {
        std::ofstream output(prefix + ".resume", std::ios::app);
        output << "unexpected\n";
    }
    assert(!manifest.load());
    manifest.remove();
    assert(!manifest.load());

    auto checkFile = [&](std::size_t size, std::size_t expectedPieces) {
        std::string path = prefix + "-" + std::to_string(size) + ".bin";
        std::ofstream(path, std::ios::binary) << std::string(size, 'x');
        FileMetadata hashed;
        assert(PieceFile::hash(path, hashed));
        assert(hashed.size == size && hashed.pieceHashes.size() == expectedPieces);
        assert(isSha1Hex(hashed.fullHash));
        unlink(path.c_str());
    };
    checkFile(0, 0);
    checkFile(17, 1);
    checkFile(PIECE_SIZE, 1);
    checkFile(PIECE_SIZE + 17, 2);
    FileMetadata ignored;
    assert(!PieceFile::hash("/tmp", ignored));

    // Pieces written out of order read back in place.
    std::string path = prefix + ".pieces";
    {
        PieceFile file = PieceFile::openForWriting(path, PIECE_SIZE + 3, false);
        assert(file && file.write(1, "end") && file.write(0, std::string(PIECE_SIZE, 'a')));
        std::string data;
        assert(file.read(1, 3, data) && data == "end");
    }
    unlink(path.c_str());

    std::cout << "resume tests passed\n";
}

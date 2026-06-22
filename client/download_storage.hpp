#pragma once

#include "client_types.hpp"

#include <string>
#include <vector>

bool saveResumeLocked(const ResumeState &resume);
bool loadResume(const std::string &manifestPath, const std::string &group,
                const std::string &name, const LocalFile &metadata,
                std::string &temporaryPath,
                std::vector<unsigned char> &verified);
bool verifyStoredPieces(int descriptor, const LocalFile &metadata,
                        std::vector<unsigned char> &verified);

bool hashFile(const std::string &path, u64 &size, std::string &fullHash,
              std::vector<std::string> &pieceHashes);
std::string joinHashes(const std::vector<std::string> &hashes);
bool writePiece(int descriptor, std::size_t index, const std::string &piece);

std::string baseName(const std::string &path);
std::string resolvedDestination(const std::string &destination,
                                const std::string &name);

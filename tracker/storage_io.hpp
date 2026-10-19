#pragma once

// File and byte helpers for the tracker's on-disk Raft state.

#include "../common/encoding.hpp"

#include <libnuraft/nuraft.hxx>

#include <string>

namespace storage_io {

std::string toString(nuraft::buffer &buffer);
nuraft::ptr<nuraft::buffer> toBuffer(const std::string &bytes);

bool readFile(const std::string &path, std::string &contents);
// Writes a temporary file, fsyncs it, then renames it over path.
bool writeFileAtomic(const std::string &path, const std::string &contents);
bool appendFileSynced(const std::string &path, const std::string &contents);

// Big-endian 8-byte integers.
void putU64(std::string &out, u64 value);
bool getU64(const std::string &in, std::size_t &position, u64 &value);

}  // namespace storage_io

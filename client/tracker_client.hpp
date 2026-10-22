#pragma once

/// @file tracker_client.hpp
/// The client's connection to the tracker.

#include "common/config/client_config.hpp"
#include "common/file_metadata.hpp"
#include "common/peer_ticket.hpp"

#include <mutex>
#include <string>
#include <vector>

/// Sends commands to the tracker over SecureChannel and remembers the
/// session ID it hands out, so later commands run as the logged-in user.
///
/// Thread-safe: requests from the prompt and from download threads are
/// serialized, one at a time.
class TrackerClient {
public:
    /// @param config  The tracker's address and pinned public key.
    /// @param self    This client's peer server address, given to the
    ///                tracker when sharing so downloaders can reach it.
    /// @param peerKey This client's raw 32-byte peer key (see
    ///                peer_ticket.hpp); also given to the tracker when sharing.
    TrackerClient(ClientConfig config, Endpoint self, std::string peerKey);

    /// Sends one command and updates the stored session from the reply.
    /// @param command  A tracker command line, e.g. "list_files demo".
    /// @param response Receives the tracker's reply ("OK ...", "ERR ...",
    ///                 "META ...") without the trailing session, or
    ///                 "ERR tracker unavailable" / "ERR invalid tracker reply".
    /// @return true if the tracker answered (even with "ERR ..."); false if
    ///         it couldn't be reached or authenticated.
    bool request(const std::string &command, std::string &response);

    /// Registers this client as a seeder of a file (upload_file), sending
    /// the metadata, this client's address and its peer key.
    /// @param name     The file name (sent hex-encoded).
    /// @param response Receives the tracker's reply.
    /// @return As for request().
    bool share(const std::string &group, const std::string &name, const FileMetadata &metadata,
               std::string &response);

    /// Asks for a file's metadata and a fresh ticket for each seeder
    /// (download_file).
    /// @param metadata Receives the validated size and hashes.
    /// @param seeders  Receives one SeederAccess per seeder; entries that
    ///                 don't parse are skipped.
    /// @param error    On failure, the message to show the user.
    /// @return true if the metadata is valid and at least one seeder parsed.
    bool locate(const std::string &group, const std::string &name, FileMetadata &metadata,
                std::vector<SeederAccess> &seeders, std::string &error);

private:
    ClientConfig config_;
    Endpoint self_;
    std::string peerKey_;
    std::mutex mutex_;   ///< One request at a time; guards session_.
    u64 session_ = 0;    ///< 0 until logged in.
};

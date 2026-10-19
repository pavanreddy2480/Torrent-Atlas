#pragma once

// Talks to the tracker cluster. Tries the last known leader first, follows
// REDIRECTs, skips trackers that are down, waits briefly while the cluster
// elects a leader, and remembers the session ID the tracker hands out.

#include "../common/client_config.hpp"
#include "../common/file_metadata.hpp"

#include <mutex>
#include <string>
#include <vector>

class TrackerClient {
public:
    // self is this client's peer address, which the tracker gives downloaders.
    TrackerClient(ClientConfig config, Endpoint self);

    // Sends one command; response is the tracker's reply without the session.
    bool request(const std::string &command, std::string &response);

    // Registers this client as a seeder of the file (upload_file).
    bool share(const std::string &group, const std::string &name, const FileMetadata &metadata,
               std::string &response);

    // Gets a file's metadata and seeders (download_file). On failure, error
    // is the message to show.
    bool locate(const std::string &group, const std::string &name, FileMetadata &metadata,
                std::vector<Endpoint> &seeders, std::string &error);

private:
    ClientConfig config_;
    Endpoint self_;
    std::mutex mutex_;
    std::size_t leader_ = 0;   // index into config_.trackers
    u64 session_ = 0;
};

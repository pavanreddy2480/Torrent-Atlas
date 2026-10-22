#pragma once

// Talks to the tracker and remembers the session ID it hands out.

#include "common/config/client_config.hpp"
#include "common/file_metadata.hpp"
#include "common/peer_ticket.hpp"

#include <mutex>
#include <string>
#include <vector>

class TrackerClient {
public:
    // self is this client's peer address and peerKey its peer key (see
    // peer_ticket.hpp); the tracker uses both to send downloaders here.
    TrackerClient(ClientConfig config, Endpoint self, std::string peerKey);

    // Sends one command; response is the tracker's reply without the session.
    bool request(const std::string &command, std::string &response);

    // Registers this client as a seeder of the file (upload_file).
    bool share(const std::string &group, const std::string &name, const FileMetadata &metadata,
               std::string &response);

    // Gets a file's metadata and a ticket for each seeder (download_file). On
    // failure, error is the message to show.
    bool locate(const std::string &group, const std::string &name, FileMetadata &metadata,
                std::vector<SeederAccess> &seeders, std::string &error);

private:
    ClientConfig config_;
    Endpoint self_;
    std::string peerKey_;
    std::mutex mutex_;
    u64 session_ = 0;
};

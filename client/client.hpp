#pragma once

// The peer program: a command prompt, a peer server that seeds files, and the
// downloads in progress.

#include "client/command_line.hpp"
#include "client/download/download_manager.hpp"
#include "client/peer/peer_server.hpp"
#include "client/peer/peer_stats.hpp"
#include "client/storage/shared_files.hpp"
#include "client/tracker_client.hpp"

#include <istream>
#include <ostream>

class Client {
public:
    Client(Endpoint self, ClientConfig config);

    // Reads commands until "quit" or end of input.
    int run(std::istream &in, std::ostream &out);

private:
    void execute(CommandLine &command, std::ostream &out);
    void uploadFile(const std::string &group, const std::string &path, std::ostream &out);
    void forwardToTracker(CommandLine &command, std::ostream &out);

    // Declared in this order so downloads stop before the peer server.
    Endpoint self_;
    TrackerClient tracker_;
    SharedFiles shared_;
    PeerStats peerStats_;
    PeerServer peerServer_;
    DownloadManager downloads_;
};

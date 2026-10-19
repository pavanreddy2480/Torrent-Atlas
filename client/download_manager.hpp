#pragma once

// Starts downloads on their own threads and answers the commands that list,
// measure and cancel them.

#include "download.hpp"

#include <memory>
#include <mutex>
#include <ostream>
#include <thread>
#include <vector>

class DownloadManager {
public:
    DownloadManager(TrackerClient &tracker, SharedFiles &shared, PeerStats &peerStats)
        : tracker_(tracker), shared_(shared), peerStats_(peerStats) {}
    ~DownloadManager();   // cancels unfinished downloads and waits for them

    void start(const std::string &group, const std::string &name, const std::string &destination,
               std::ostream &out);
    void cancel(const std::string &name, std::ostream &out);
    void printDownloads(std::ostream &out) const;
    void printStats(std::ostream &out) const;

private:
    TrackerClient &tracker_;
    SharedFiles &shared_;
    PeerStats &peerStats_;
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<Download>> downloads_;
    std::vector<std::thread> threads_;
};

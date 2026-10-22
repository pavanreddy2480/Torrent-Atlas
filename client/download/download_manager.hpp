#pragma once

/// @file download_manager.hpp
/// Every download this client has started.

#include "client/download/download.hpp"

#include <memory>
#include <mutex>
#include <ostream>
#include <thread>
#include <vector>

/// Starts each Download on its own thread and answers the commands that
/// list, measure and cancel them. Thread-safe. Keeps finished downloads so
/// show_downloads can report them.
class DownloadManager {
public:
    /// The references must outlive the manager.
    DownloadManager(TrackerClient &tracker, SharedFiles &shared, PeerStats &peerStats)
        : tracker_(tracker), shared_(shared), peerStats_(peerStats) {}
    /// Cancels unfinished downloads and waits for every download thread.
    ~DownloadManager();

    /// Starts a download in the background. If destination is a directory,
    /// the file is saved in it under its own name. Prints "OK download
    /// started" or the reason it couldn't start: the destination exists or
    /// is already being downloaded, or the tracker refused (not a member,
    /// no seeders, ...).
    void start(const std::string &group, const std::string &name, const std::string &destination,
               std::ostream &out);
    /// Cancels the most recent unfinished download of a file with this name.
    /// Prints whether one was found.
    void cancel(const std::string &name, std::ostream &out);
    /// Prints one summary line per download, oldest first.
    void printDownloads(std::ostream &out) const;
    /// Prints each download's stats and an aggregate line.
    void printStats(std::ostream &out) const;

private:
    TrackerClient &tracker_;
    SharedFiles &shared_;
    PeerStats &peerStats_;
    mutable std::mutex mutex_;   ///< Guards downloads_ and threads_.
    std::vector<std::shared_ptr<Download>> downloads_;
    std::vector<std::thread> threads_;
};

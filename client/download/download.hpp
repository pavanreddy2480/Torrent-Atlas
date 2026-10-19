#pragma once

// One download. It asks every seeder which pieces it has, fetches the rarest
// pieces first with up to eight threads, checks each piece's SHA-1, and
// records progress in a resume manifest. Verified pieces are shared with other
// peers right away. The finished file is checked against the full SHA-1
// before it replaces <destination>.part.

#include "client/peer/peer_client.hpp"
#include "client/storage/piece_file.hpp"
#include "client/download/resume_manifest.hpp"
#include "client/storage/shared_files.hpp"
#include "client/tracker_client.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <ostream>
#include <string>
#include <vector>

class Download {
public:
    Download(std::string group, std::string name, std::string destination, FileMetadata metadata,
             std::vector<Endpoint> seeders, TrackerClient &tracker, SharedFiles &shared,
             PeerStats &peerStats);

    void run();
    void cancel() { cancelled_ = true; }

    bool finished() const { return finished_; }
    const std::string &name() const { return name_; }
    const std::string &destination() const { return destination_; }

    u64 totalBytes() const { return metadata_.size; }
    u64 transferredBytes() const { return verifiedBytes_ - resumedBytes_; }
    double elapsedSeconds() const;

    void printSummary(std::ostream &out) const;   // one line for show_downloads
    void printStats(std::ostream &out) const;     // a block for stats

private:
    bool prepare();
    void fetchBitmaps();
    std::vector<std::size_t> rarestFirst();
    bool fetchPieces(const std::vector<std::size_t> &order);
    bool fetchPiece(std::size_t piece);
    void markVerified(std::size_t piece);
    void complete();
    void finish(bool failed, const std::string &reason = "");
    void countFailure(TransferResult result);
    char state() const { return finished_ ? (failed_ ? 'F' : 'C') : 'D'; }

    const std::string group_;
    const std::string name_;
    const std::string destination_;
    const std::string partPath_;
    const FileMetadata metadata_;
    const std::vector<Endpoint> seeders_;
    TrackerClient &tracker_;
    SharedFiles &shared_;
    PeerClient peers_;
    ResumeManifest manifest_;
    PieceFile file_;

    std::mutex mutex_;   // guards verified_ and the manifest file
    std::vector<bool> verified_;
    std::vector<std::vector<bool>> seederBitmaps_;
    std::vector<std::size_t> rarity_;   // how many seeders have each piece

    const std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::atomic<double> elapsed_{0.0};
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> finished_{false};
    std::atomic<bool> failed_{false};
    mutable std::mutex reasonMutex_;
    std::string failureReason_;

    // Counters shown by show_downloads and stats.
    std::atomic<std::size_t> completed_{0};
    std::atomic<std::size_t> resumedPieces_{0};
    std::atomic<std::size_t> rarePieces_{0};
    std::atomic<std::size_t> responsiveSeeders_{0};
    std::atomic<u64> verifiedBytes_{0};
    std::atomic<u64> resumedBytes_{0};
    std::atomic<u64> retries_{0};
    std::atomic<u64> networkFailures_{0};
    std::atomic<u64> authenticationFailures_{0};
    std::atomic<u64> unavailable_{0};
    std::atomic<u64> integrityFailures_{0};
};

#pragma once

/// @file download.hpp
/// One file download, from resume check to verified final file.

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

/// Downloads one file from its seeders.
///
/// run() goes through these steps:
///  1. prepare(): open <destination>.part and keep any pieces a resume
///     manifest claims, after re-hashing them.
///  2. fetchBitmaps(): ask every seeder which pieces it has.
///  3. Start seeding the pieces we already have, and register with the
///     tracker as a seeder.
///  4. fetchPieces(): fetch missing pieces rarest-first on up to eight
///     threads, checking each piece's SHA-1 and saving progress.
///  5. complete(): check the whole file's SHA-1 and rename .part into place.
///
/// Seeder tickets last five minutes, so seederAt() asks the tracker for
/// fresh ones shortly before they expire.
///
/// Threading: run() executes on its own thread (DownloadManager starts it);
/// cancel(), the getters and the print methods may be called from the
/// prompt thread at any time.
class Download {
public:
    /// @param destination Final path; .part and .resume files sit beside it.
    /// @param metadata    The file's validated size and hashes.
    /// @param seeders     Where to fetch from, with their tickets.
    /// @param tracker     For registering as a seeder and renewing tickets.
    /// @param shared      Where verified pieces are published to the peer server.
    /// @param peerStats   Where every peer request's outcome is recorded.
    Download(std::string group, std::string name, std::string destination, FileMetadata metadata,
             std::vector<SeederAccess> seeders, TrackerClient &tracker, SharedFiles &shared,
             PeerStats &peerStats);

    /// Runs the whole download (see the class comment); blocks until it
    /// completes, fails or is cancelled. Call once.
    void run();
    /// Asks run() to stop soon. Pieces already verified stay on disk and in
    /// the resume manifest. Thread-safe.
    void cancel() { cancelled_ = true; }

    /// @return true once run() has finished, successfully or not.
    bool finished() const { return finished_; }
    const std::string &name() const { return name_; }
    const std::string &destination() const { return destination_; }

    /// @return The file's size in bytes.
    u64 totalBytes() const { return metadata_.size; }
    /// @return Bytes fetched from peers in this run (excludes resumed pieces).
    u64 transferredBytes() const { return verifiedBytes_ - resumedBytes_; }
    /// @return Seconds since the download started (frozen once finished);
    ///         at least 0.001 so it is safe to divide by.
    double elapsedSeconds() const;

    /// Prints one line for show_downloads: [D]ownloading, [C]omplete or
    /// [F]ailed, progress, and the failure reason if any.
    void printSummary(std::ostream &out) const;
    /// Prints a block for stats: progress, speed, ETA, peers and retries.
    void printStats(std::ostream &out) const;

private:
    /// Opens the .part file and loads resume data, re-hashing every piece it
    /// claims. On failure calls finish(true, ...).
    /// @return false if the download can't proceed.
    bool prepare();
    /// Asks each seeder for its bitmap; fills seederBitmaps_ and rarity_.
    void fetchBitmaps();
    /// @return The missing pieces, fewest holders first, ties by index.
    std::vector<std::size_t> rarestFirst();
    /// Fetches the pieces in order on up to MAX_THREADS worker threads.
    /// @return true if every piece was fetched.
    bool fetchPieces(const std::vector<std::size_t> &order);
    /// Tries each seeder that has the piece, for a few rounds with backoff.
    /// @return true once the piece is verified and written.
    bool fetchPiece(std::size_t piece);
    /// Syncs the file, records the piece in the manifest, and publishes it
    /// to the peer server.
    void markVerified(std::size_t piece);
    /// Checks the full-file SHA-1, renames .part into place, deletes the
    /// manifest and seeds the complete file.
    void complete();
    /// Records the outcome and stops the clock.
    void finish(bool failed, const std::string &reason = "");
    /// Counts one failed peer request by its kind.
    void countFailure(TransferResult result);
    /// @return Seeder index's access, first renewing every ticket from the
    ///         tracker if they are about to expire. Thread-safe.
    SeederAccess seederAt(std::size_t index);
    /// Sets refreshAt_ to a minute before the earliest ticket expires (but
    /// at least 30 s from now). seedersMutex_ must be held.
    void scheduleTicketRefresh();
    /// @return 'D' downloading, 'C' complete or 'F' failed.
    char state() const { return finished_ ? (failed_ ? 'F' : 'C') : 'D'; }

    const std::string group_;
    const std::string name_;
    const std::string destination_;
    const std::string partPath_;
    const FileMetadata metadata_;
    std::mutex seedersMutex_;   ///< Guards seeders_ and refreshAt_.
    std::vector<SeederAccess> seeders_;
    long long refreshAt_ = 0;   ///< Unix seconds; when to renew tickets.
    TrackerClient &tracker_;
    SharedFiles &shared_;
    PeerClient peers_;
    ResumeManifest manifest_;
    PieceFile file_;

    std::mutex mutex_;   ///< Guards verified_ and the manifest file.
    std::vector<bool> verified_;
    std::vector<std::vector<bool>> seederBitmaps_;
    std::vector<std::size_t> rarity_;   ///< How many seeders have each piece.

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

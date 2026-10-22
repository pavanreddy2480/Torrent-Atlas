#include "client/download/download.hpp"

#include "common/crypto/crypto.hpp"
#include "common/net/freshness.hpp"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <random>
#include <thread>

namespace {

constexpr std::size_t MAX_THREADS = 8;
constexpr int ROUNDS_PER_PIECE = 3;

// Exponential backoff with jitter: about 150 ms, 300 ms, 600 ms...
std::chrono::milliseconds retryDelay(int round) {
    thread_local std::mt19937 random{std::random_device{}()};
    return std::chrono::milliseconds(150 * (1 << std::min(round, 4)) +
                                     std::uniform_int_distribution<int>(0, 100)(random));
}

constexpr double MIB = 1024.0 * 1024.0;

// Fetch new tickets this long before the current ones expire, and wait this
// long before asking again if the tracker says no.
constexpr long long TICKET_MARGIN_SECONDS = 60;
constexpr long long TICKET_RETRY_SECONDS = 30;

}  // namespace

Download::Download(std::string group, std::string name, std::string destination,
                   FileMetadata metadata, std::vector<SeederAccess> seeders, TrackerClient &tracker,
                   SharedFiles &shared, PeerStats &peerStats)
    : group_(std::move(group)), name_(std::move(name)), destination_(std::move(destination)),
      partPath_(destination_ + ".part"), metadata_(std::move(metadata)),
      seeders_(std::move(seeders)), tracker_(tracker), shared_(shared), peers_(peerStats),
      manifest_(destination_ + ".resume", group_, name_, metadata_, partPath_) {
    scheduleTicketRefresh();
}

void Download::scheduleTicketRefresh() {
    long long earliest = 0;
    for (const SeederAccess &seeder : seeders_)
        earliest = earliest ? std::min(earliest, seeder.expires()) : seeder.expires();
    refreshAt_ = std::max(earliest - TICKET_MARGIN_SECONDS, unixSeconds() + TICKET_RETRY_SECONDS);
}

SeederAccess Download::seederAt(std::size_t index) {
    std::lock_guard<std::mutex> lock(seedersMutex_);
    if (unixSeconds() >= refreshAt_) {
        FileMetadata ignored;
        std::vector<SeederAccess> fresh;
        std::string error;
        if (tracker_.locate(group_, name_, ignored, fresh, error))
            for (SeederAccess &current : seeders_)
                for (const SeederAccess &update : fresh)
                    if (update.endpoint == current.endpoint) current = update;
        scheduleTicketRefresh();
    }
    return seeders_[index];
}

void Download::run() {
    if (!prepare()) return;
    fetchBitmaps();

    // Serve the pieces we already have while the rest download.
    shared_.add(group_, name_, {partPath_, metadata_, verified_});
    std::string ignored;
    tracker_.share(group_, name_, metadata_, ignored);

    bool gotAll = fetchPieces(rarestFirst());
    file_ = PieceFile();
    if (cancelled_) return finish(true, "cancelled by user; resume data retained");
    if (!gotAll) return finish(true, "one or more pieces could not be reconstructed");
    complete();
}

// Opens <destination>.part, keeping pieces a resume manifest says are done
// if they still match their hashes.
bool Download::prepare() {
    std::optional<std::vector<bool>> resumed = manifest_.load();
    std::error_code error;
    bool resuming = resumed && std::filesystem::is_regular_file(partPath_, error) &&
                    std::filesystem::file_size(partPath_, error) == metadata_.size;
    file_ = PieceFile::openForWriting(partPath_, metadata_.size, resuming);
    if (!file_) {
        finish(true, "unable to create destination file");
        return false;
    }
    verified_ = resuming ? *resumed : std::vector<bool>(metadata_.pieceCount(), false);
    std::string data;
    for (std::size_t piece = 0; piece < verified_.size(); ++piece) {
        if (!verified_[piece]) continue;
        verified_[piece] = file_.read(piece, metadata_.pieceLength(piece), data) &&
                           crypto::sha1Hex(data) == metadata_.pieceHashes[piece];
        if (verified_[piece]) {
            ++resumedPieces_;
            resumedBytes_ += data.size();
        }
    }
    completed_ = resumedPieces_.load();
    verifiedBytes_ = resumedBytes_.load();
    if (!manifest_.save(verified_)) {
        finish(true, "unable to persist resume manifest");
        return false;
    }
    return true;
}

void Download::fetchBitmaps() {
    seederBitmaps_.assign(seeders_.size(), {});
    rarity_.assign(metadata_.pieceCount(), 0);
    for (std::size_t seeder = 0; seeder < seeders_.size(); ++seeder) {
        std::vector<bool> &bitmap = seederBitmaps_[seeder];
        TransferResult result =
            peers_.fetchBitmap(seederAt(seeder), metadata_.pieceCount(), bitmap);
        if (result != TransferResult::Success) {
            countFailure(result);
            continue;
        }
        ++responsiveSeeders_;
        for (std::size_t piece = 0; piece < bitmap.size(); ++piece) rarity_[piece] += bitmap[piece];
    }
    if (!rarity_.empty())
        rarePieces_ = std::count(rarity_.begin(), rarity_.end(),
                                 *std::min_element(rarity_.begin(), rarity_.end()));
}

std::vector<std::size_t> Download::rarestFirst() {
    std::vector<std::size_t> order;
    for (std::size_t piece = 0; piece < verified_.size(); ++piece)
        if (!verified_[piece]) order.push_back(piece);
    std::stable_sort(order.begin(), order.end(),
                     [&](std::size_t a, std::size_t b) { return rarity_[a] < rarity_[b]; });
    return order;
}

bool Download::fetchPieces(const std::vector<std::size_t> &order) {
    std::atomic<std::size_t> next{0};
    std::atomic<bool> failed{false};
    std::size_t threadCount = std::min({MAX_THREADS, seeders_.size(), order.size()});
    std::vector<std::thread> threads;
    for (std::size_t i = 0; i < threadCount; ++i)
        threads.emplace_back([&] {
            for (std::size_t position; !cancelled_ && (position = next++) < order.size();)
                if (!fetchPiece(order[position]) && !cancelled_) failed = true;
        });
    for (std::thread &thread : threads) thread.join();
    return !failed;
}

// Tries every seeder that has the piece, a few rounds with backoff.
bool Download::fetchPiece(std::size_t piece) {
    std::vector<std::size_t> candidates;
    for (std::size_t seeder = 0; seeder < seeders_.size(); ++seeder)
        if (piece < seederBitmaps_[seeder].size() && seederBitmaps_[seeder][piece])
            candidates.push_back(seeder);
    // Start at a different seeder for each piece to spread the load.
    if (!candidates.empty())
        std::rotate(candidates.begin(), candidates.begin() + piece % candidates.size(),
                    candidates.end());

    for (int round = 0; round < ROUNDS_PER_PIECE && !cancelled_; ++round) {
        for (std::size_t seeder : candidates) {
            if (cancelled_) return false;
            std::string data;
            TransferResult result =
                peers_.fetchPiece(seederAt(seeder), piece, metadata_.pieceHashes[piece], data);
            if (result != TransferResult::Success) {
                countFailure(result);
            } else if (file_.write(piece, data)) {
                markVerified(piece);
                return true;
            }
        }
        if (!cancelled_) std::this_thread::sleep_for(retryDelay(round));
    }
    return false;
}

void Download::markVerified(std::size_t piece) {
    file_.sync();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        verified_[piece] = true;
        manifest_.save(verified_);
    }
    verifiedBytes_ += metadata_.pieceLength(piece);
    ++completed_;
    shared_.markAvailable(group_, name_, piece);
}

// Checks the whole file, moves it into place and seeds it.
void Download::complete() {
    FileMetadata actual;
    if (!PieceFile::hash(partPath_, actual)) return finish(true, "final file hashing failed");
    if (actual.size != metadata_.size || actual.fullHash != metadata_.fullHash)
        return finish(true, "final SHA1 integrity check failed");
    std::error_code error;
    std::filesystem::rename(partPath_, destination_, error);
    if (error) return finish(true, "unable to move completed file into place");
    manifest_.remove();
    std::string ignored;
    tracker_.share(group_, name_, metadata_, ignored);
    shared_.add(group_, name_, {destination_, metadata_, std::vector<bool>(metadata_.pieceCount(), true)});
    finish(false);
}

void Download::finish(bool failed, const std::string &reason) {
    {
        std::lock_guard<std::mutex> lock(reasonMutex_);
        failureReason_ = reason;
    }
    failed_ = failed;
    elapsed_ = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
    finished_ = true;
}

void Download::countFailure(TransferResult result) {
    ++retries_;
    switch (result) {
    case TransferResult::NetworkFailure: ++networkFailures_; break;
    case TransferResult::AuthenticationFailure: ++authenticationFailures_; break;
    case TransferResult::Unavailable: ++unavailable_; break;
    case TransferResult::IntegrityFailure: ++integrityFailures_; break;
    case TransferResult::Success: break;
    }
}

double Download::elapsedSeconds() const {
    double seconds = finished_ ? elapsed_.load()
                               : std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                                               started_).count();
    return std::max(0.001, seconds);
}

void Download::printSummary(std::ostream &out) const {
    out << '[' << state() << "] [" << group_ << "] " << name_;
    if (!finished_) out << " (" << completed_ << '/' << metadata_.pieceCount() << " pieces)";
    out << " rare=" << rarePieces_ << " resumed=" << resumedPieces_
        << " integrity-failures=" << integrityFailures_;
    std::lock_guard<std::mutex> lock(reasonMutex_);
    if (failed_ && !failureReason_.empty()) out << " reason=\"" << failureReason_ << '"';
    out << '\n';
}

void Download::printStats(std::ostream &out) const {
    u64 verified = verifiedBytes_;
    double elapsed = elapsedSeconds();
    double speed = transferredBytes() / elapsed / MIB;
    double progress = metadata_.size ? 100.0 * verified / metadata_.size : 100.0;
    double eta = speed > 0.0 && verified < metadata_.size
                     ? (metadata_.size - verified) / (speed * MIB)
                     : 0.0;
    out << '[' << state() << "] [" << group_ << "] " << name_ << '\n'
        << std::fixed << std::setprecision(1)
        << "  progress: " << progress << "% (" << completed_ << '/' << metadata_.pieceCount()
        << " pieces, " << verified / (1024 * 1024) << '/' << metadata_.size / (1024 * 1024)
        << " MiB)\n"
        << "  speed: " << speed << " MiB/s  elapsed: " << elapsed << "s  eta: " << eta << "s\n"
        << "  peers: " << responsiveSeeders_ << '/' << seeders_.size() << " responsive\n"
        << "  scheduler: rare=" << rarePieces_ << " resumed=" << resumedPieces_ << '\n'
        << "  reliability: retries=" << retries_ << " network=" << networkFailures_
        << " auth=" << authenticationFailures_ << " unavailable=" << unavailable_
        << " corrupt=" << integrityFailures_ << '\n';
}

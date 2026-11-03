#include "client/download/download.hpp"

#include "common/crypto/crypto.hpp"
#include "common/net/freshness.hpp"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <thread>

namespace {

constexpr std::size_t MAX_THREADS = 8;
constexpr std::size_t PASSES_PER_PIECE = 3;
constexpr std::chrono::milliseconds PASS_PAUSE{200};

// Fetch new tickets when the current one expires within this many seconds.
constexpr long long TICKET_MARGIN_SECONDS = 60;

constexpr double MIB = 1024.0 * 1024.0;

}  // namespace

Download::Download(std::string group, std::string name, std::string destination,
                   FileMetadata metadata, std::vector<SeederAccess> seeders, TrackerClient &tracker,
                   SharedFiles &shared, PeerStats &peerStats)
    : group_(std::move(group)), name_(std::move(name)), destination_(std::move(destination)),
      partPath_(destination_ + ".part"), metadata_(std::move(metadata)),
      seeders_(std::move(seeders)), tracker_(tracker), shared_(shared), peers_(peerStats) {}

SeederAccess Download::seederAt(std::size_t index) {
    std::lock_guard<std::mutex> lock(seedersMutex_);
    if (seeders_[index].expires() - unixSeconds() < TICKET_MARGIN_SECONDS) {
        FileMetadata ignored;
        std::vector<SeederAccess> fresh;
        std::string error;
        if (tracker_.locate(group_, name_, ignored, fresh, error))
            for (SeederAccess &current : seeders_)
                for (const SeederAccess &update : fresh)
                    if (update.endpoint == current.endpoint) current = update;
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
    if (cancelled_) return finish(true, "cancelled by user; partial file kept for resume");
    if (!gotAll) return finish(true, "one or more pieces could not be reconstructed");
    complete();
}

// Opens <destination>.part. Any piece already in it that matches its hash is
// kept, so a later download of the same file resumes where this one stopped.
bool Download::prepare() {
    std::error_code error;
    bool resuming = std::filesystem::exists(partPath_, error);
    file_ = PieceFile::openForWriting(partPath_, metadata_.size, true);
    if (!file_) {
        finish(true, "unable to create destination file");
        return false;
    }
    verified_.assign(metadata_.pieceCount(), false);
    std::string data;
    for (std::size_t piece = 0; resuming && piece < verified_.size(); ++piece) {
        verified_[piece] = file_.read(piece, metadata_.pieceLength(piece), data) &&
                           crypto::sha1Hex(data) == metadata_.pieceHashes[piece];
        if (verified_[piece]) {
            ++resumedPieces_;
            resumedBytes_ += data.size();
        }
    }
    completed_ = resumedPieces_.load();
    verifiedBytes_ = resumedBytes_.load();
    return true;
}

void Download::fetchBitmaps() {
    seederBitmaps_.assign(seeders_.size(), {});
    rarity_.assign(metadata_.pieceCount(), 0);
    for (std::size_t seeder = 0; seeder < seeders_.size(); ++seeder) {
        std::vector<bool> &bitmap = seederBitmaps_[seeder];
        if (peers_.fetchBitmap(seederAt(seeder), metadata_.pieceCount(), bitmap) !=
            TransferResult::Success) {
            ++retries_;
            continue;
        }
        for (std::size_t piece = 0; piece < bitmap.size(); ++piece) rarity_[piece] += bitmap[piece];
    }
}

std::vector<std::size_t> Download::rarestFirst() const {
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

bool Download::fetchPiece(std::size_t piece) {
    std::vector<std::size_t> holders;
    for (std::size_t seeder = 0; seeder < seeders_.size(); ++seeder)
        if (piece < seederBitmaps_[seeder].size() && seederBitmaps_[seeder][piece])
            holders.push_back(seeder);

    std::size_t attempts = PASSES_PER_PIECE * holders.size();
    for (std::size_t attempt = 0; attempt < attempts && !cancelled_; ++attempt) {
        // Starting at piece % holders spreads the pieces over the seeders.
        std::size_t seeder = holders[(piece + attempt) % holders.size()];
        std::string data;
        TransferResult result =
            peers_.fetchPiece(seederAt(seeder), piece, metadata_.pieceHashes[piece], data);
        if (result == TransferResult::Success && file_.write(piece, data)) {
            markVerified(piece);
            return true;
        }
        ++retries_;
        if (result == TransferResult::IntegrityFailure) ++integrityFailures_;
        // Pause after each full pass over the holders.
        if ((attempt + 1) % holders.size() == 0) std::this_thread::sleep_for(PASS_PAUSE);
    }
    return false;
}

void Download::markVerified(std::size_t piece) {
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
    std::string ignored;
    tracker_.share(group_, name_, metadata_, ignored);
    shared_.add(group_, name_, {destination_, metadata_, std::vector<bool>(metadata_.pieceCount(), true)});
    finish(false);
}

void Download::finish(bool failed, const std::string &reason) {
    std::lock_guard<std::mutex> lock(statusMutex_);
    failureReason_ = reason;
    failed_ = failed;
    elapsed_ = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
    finished_ = true;
}

bool Download::finished() const {
    std::lock_guard<std::mutex> lock(statusMutex_);
    return finished_;
}

char Download::state() const {
    std::lock_guard<std::mutex> lock(statusMutex_);
    return finished_ ? (failed_ ? 'F' : 'C') : 'D';
}

double Download::elapsedSeconds() const {
    std::lock_guard<std::mutex> lock(statusMutex_);
    double seconds = finished_ ? elapsed_
                               : std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                                               started_).count();
    return std::max(0.001, seconds);
}

void Download::printSummary(std::ostream &out) const {
    char current = state();
    out << '[' << current << "] [" << group_ << "] " << name_;
    if (current == 'D') out << " (" << completed_ << '/' << metadata_.pieceCount() << " pieces)";
    out << " resumed=" << resumedPieces_ << " integrity-failures=" << integrityFailures_;
    std::lock_guard<std::mutex> lock(statusMutex_);
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
        << " MiB, " << resumedPieces_ << " resumed)\n"
        << "  speed: " << speed << " MiB/s  elapsed: " << elapsed << "s  eta: " << eta << "s\n"
        << "  peers: " << seeders_.size() << " seeders, retries=" << retries_
        << " corrupt=" << integrityFailures_ << '\n';
}

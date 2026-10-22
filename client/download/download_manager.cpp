#include "client/download/download_manager.hpp"

#include <filesystem>
#include <iomanip>

namespace fs = std::filesystem;

DownloadManager::~DownloadManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &download : downloads_) download->cancel();
    for (std::thread &thread : threads_) thread.join();
}

void DownloadManager::start(const std::string &group, const std::string &name,
                            const std::string &destination, std::ostream &out) {
    // A directory destination means "save under the file's own name in it".
    std::error_code error;
    std::string path = fs::is_directory(destination, error) ? (fs::path(destination) / name).string()
                                                            : destination;
    if (fs::exists(path, error)) {
        out << "ERR destination already exists: " << path << '\n';
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &download : downloads_)
            if (!download->finished() && download->destination() == path) {
                out << "ERR destination is already being downloaded: " << path << '\n';
                return;
            }
    }
    FileMetadata metadata;
    std::vector<SeederAccess> seeders;
    std::string message;
    if (!tracker_.locate(group, name, metadata, seeders, message)) {
        out << message << '\n';
        return;
    }
    auto download = std::make_shared<Download>(group, name, path, metadata, seeders, tracker_,
                                               shared_, peerStats_);
    std::lock_guard<std::mutex> lock(mutex_);
    downloads_.push_back(download);
    threads_.emplace_back([download] { download->run(); });
    out << "OK download started\n";
}

void DownloadManager::cancel(const std::string &name, std::ostream &out) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto download = downloads_.rbegin(); download != downloads_.rend(); ++download)
        if ((*download)->name() == name && !(*download)->finished()) {
            (*download)->cancel();
            out << "OK cancellation requested\n";
            return;
        }
    out << "ERR no active download with that name\n";
}

void DownloadManager::printDownloads(std::ostream &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &download : downloads_) download->printSummary(out);
}

void DownloadManager::printStats(std::ostream &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (downloads_.empty()) {
        out << "No downloads recorded\n";
        return;
    }
    u64 transferred = 0, scheduled = 0;
    double seconds = 0.0;
    for (const auto &download : downloads_) {
        download->printStats(out);
        transferred += download->transferredBytes();
        scheduled += download->totalBytes();
        seconds = std::max(seconds, download->elapsedSeconds());
    }
    out << std::fixed << std::setprecision(1) << "Aggregate: " << downloads_.size()
        << " downloads, " << transferred / seconds / (1024.0 * 1024.0) << " MiB/s, "
        << scheduled / (1024 * 1024) << " MiB scheduled\n";
}

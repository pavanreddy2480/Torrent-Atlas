#include "tui_model.hpp"

#include "telemetry.hpp"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>

std::vector<DownloadView> buildDownloadViews(
    const std::vector<std::shared_ptr<DownloadStatus>> &statuses,
    const std::unordered_map<std::string, PeerReputation> &reputations) {
    std::vector<DownloadView> result;
    result.reserve(statuses.size());
    for (const auto &status : statuses) {
        sampleDownloadSpeed(status);
        DownloadView view;
        view.source = status;
        view.group = status->group;
        view.name = status->name;
        view.completed = status->completed.load();
        view.total = status->total;
        view.finished = status->finished.load();
        view.failed = status->failed.load();
        view.totalBytes = status->totalBytes.load();
        view.verifiedBytes = status->verifiedBytes.load();
        view.resumedBytes = status->resumedVerifiedBytes.load();
        view.elapsedMicros = status->finalElapsedMicroseconds.load();
        if (!view.elapsedMicros)
            view.elapsedMicros = elapsedMicroseconds(status->started);
        view.activeRequests = status->activeRequests.load();
        view.retries = status->retries.load();
        view.networkFailures = status->networkFailures.load();
        view.authenticationFailures =
            status->authenticationFailures.load();
        view.unavailableResponses = status->unavailableResponses.load();
        view.integrityFailures = status->integrityFailures.load();
        view.discoveredPeers = status->discoveredPeers.load();
        view.responsivePeers = status->responsivePeers.load();
        view.rarePieces = status->rarePieces.load();
        view.duplicateRequests = status->duplicateRequests.load();
        {
            std::lock_guard<std::mutex> lock(status->telemetryMutex);
            view.telemetry = status->telemetry;
        }
        for (auto &peer : view.telemetry.peers) {
            auto found = reputations.find(peer.endpoint);
            if (found == reputations.end()) continue;
            const PeerReputation &reputation = found->second;
            peer.trust = std::max(
                0.0, std::min(100.0,
                              100.0 -
                                  reputation.networkFailures * 2.0 -
                                  reputation.authenticationFailures * 20.0 -
                                  reputation.integrityFailures * 30.0));
            peer.throughputMiB =
                reputation.transferSeconds > 0.0
                    ? static_cast<double>(reputation.bytes) /
                          reputation.transferSeconds / (1024.0 * 1024.0)
                    : 0.0;
            peer.failures = reputation.networkFailures +
                            reputation.authenticationFailures +
                            reputation.integrityFailures;
            peer.blacklisted =
                reputation.blacklistedUntil > std::time(nullptr);
        }
        result.push_back(std::move(view));
    }
    return result;
}

double viewSpeedMiB(const DownloadView &view) {
    double seconds = std::max(0.001, view.elapsedMicros / 1000000.0);
    u64 transferred = view.verifiedBytes > view.resumedBytes
                          ? view.verifiedBytes - view.resumedBytes
                          : 0;
    return static_cast<double>(transferred) / seconds /
           (1024.0 * 1024.0);
}

std::string formatBytes(u64 bytes) {
    static const char *units[] = {"B", "KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream result;
    result << std::fixed << std::setprecision(unit == 0 ? 0 : 1)
           << value << ' ' << units[unit];
    return result.str();
}

std::string formatDuration(u64 microseconds) {
    if (microseconds < 1000000) {
        std::ostringstream shortDuration;
        shortDuration << std::fixed << std::setprecision(1)
                      << microseconds / 1000000.0 << "s";
        return shortDuration.str();
    }
    u64 seconds = microseconds / 1000000;
    std::ostringstream output;
    if (seconds >= 3600) output << seconds / 3600 << "h ";
    if (seconds >= 60) output << (seconds / 60) % 60 << "m ";
    output << seconds % 60 << "s";
    return output.str();
}

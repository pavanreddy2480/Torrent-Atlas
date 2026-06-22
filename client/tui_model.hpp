#pragma once

#include "client_types.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct DownloadView {
    std::shared_ptr<DownloadStatus> source;
    std::string group;
    std::string name;
    std::size_t completed = 0;
    std::size_t total = 0;
    bool finished = false;
    bool failed = false;
    u64 totalBytes = 0;
    u64 verifiedBytes = 0;
    u64 resumedBytes = 0;
    u64 elapsedMicros = 0;
    u64 activeRequests = 0;
    u64 retries = 0;
    u64 networkFailures = 0;
    u64 authenticationFailures = 0;
    u64 unavailableResponses = 0;
    std::size_t integrityFailures = 0;
    std::size_t discoveredPeers = 0;
    std::size_t responsivePeers = 0;
    std::size_t rarePieces = 0;
    std::size_t duplicateRequests = 0;
    DownloadTelemetry telemetry;
};

std::vector<DownloadView> buildDownloadViews(
    const std::vector<std::shared_ptr<DownloadStatus>> &statuses,
    const std::unordered_map<std::string, PeerReputation> &reputations);

double viewSpeedMiB(const DownloadView &view);
std::string formatBytes(u64 bytes);
std::string formatDuration(u64 microseconds);

#pragma once

#include "../common/protocol.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct LocalFile {
    std::string path;
    u64 size = 0;
    std::string fullHash;
    std::string capability;
    std::vector<std::string> pieceHashes;
    std::vector<unsigned char> available;
};

struct PeerInfo {
    Endpoint endpoint;
};

struct DownloadStatus {
    std::string group;
    std::string name;
    std::atomic<std::size_t> completed{0};
    std::size_t total = 0;
    std::atomic<bool> finished{false};
    std::atomic<bool> failed{false};
    std::atomic<bool> cancelRequested{false};
    std::atomic<std::size_t> integrityFailures{0};
    std::atomic<std::size_t> rarePieces{0};
    std::atomic<std::size_t> resumedPieces{0};
    std::atomic<u64> totalBytes{0};
    std::chrono::steady_clock::time_point started =
        std::chrono::steady_clock::now();
    std::atomic<u64> verifiedBytes{0};
    std::atomic<u64> resumedVerifiedBytes{0};
    std::atomic<u64> wireRequests{0};
    std::atomic<u64> retries{0};
    std::atomic<u64> networkFailures{0};
    std::atomic<u64> authenticationFailures{0};
    std::atomic<u64> unavailableResponses{0};
    std::atomic<u64> activeRequests{0};
    std::atomic<u64> cryptoMicroseconds{0};
    std::atomic<u64> networkMicroseconds{0};
    std::atomic<u64> diskMicroseconds{0};
    std::atomic<std::size_t> discoveredPeers{0};
    std::atomic<std::size_t> responsivePeers{0};
    std::atomic<u64> finalElapsedMicroseconds{0};
    std::string destinationKey;
    std::string failureReason;
};

struct PeerMetrics {
    u64 successes = 0;
    u64 networkFailures = 0;
    u64 authenticationFailures = 0;
    u64 integrityFailures = 0;
    u64 bytes = 0;
    double transferSeconds = 0.0;
};

struct ResumeState {
    std::mutex mutex;
    std::string manifestPath;
    std::string temporaryPath;
    std::string group;
    std::string name;
    LocalFile metadata;
    std::vector<unsigned char> verified;
};

enum class TransferResult {
    Success,
    NetworkFailure,
    AuthenticationFailure,
    IntegrityFailure,
    Unavailable
};

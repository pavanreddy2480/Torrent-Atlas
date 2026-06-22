#pragma once

#include "../common/protocol.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

struct Endpoint {
    std::string ip;
    int port = 0;
};

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
    std::string publicKey;
};

enum class PieceState {
    Unavailable,
    Available,
    Reserved,
    Downloading,
    Verified,
    Failed
};

struct PeerTelemetry {
    std::string endpoint;
    std::vector<unsigned char> bitmap;
    std::size_t availablePieces = 0;
    double trust = 100.0;
    double throughputMiB = 0.0;
    u64 failures = 0;
    bool blacklisted = false;
};

struct WorkerTelemetry {
    std::size_t id = 0;
    std::optional<std::size_t> piece;
    std::string peer;
    std::string state = "idle";
    std::size_t completed = 0;
    std::size_t failures = 0;
    u64 bytes = 0;
    double transferSeconds = 0.0;
};

struct DownloadTelemetry {
    std::vector<PieceState> pieces;
    std::vector<std::size_t> availability;
    std::vector<std::size_t> rarestQueue;
    std::map<std::size_t, std::vector<std::string>> reservations;
    std::vector<PeerTelemetry> peers;
    std::vector<WorkerTelemetry> workers;
    std::deque<std::string> events;
    std::deque<double> speedHistory;
    std::string destination;
    std::string failureReason;
    bool integrityVerified = false;
    std::size_t peersUsed = 0;
    std::set<std::string> peerEndpointsUsed;
    u64 lastSpeedBytes = 0;
    std::chrono::steady_clock::time_point lastSpeedSample =
        std::chrono::steady_clock::now();
};

struct DownloadStatus {
    std::string group;
    std::string name;
    std::atomic<std::size_t> completed{0};
    std::size_t total = 0;
    std::atomic<bool> finished{false};
    std::atomic<bool> failed{false};
    std::atomic<bool> cancelRequested{false};
    std::atomic<std::size_t> duplicateRequests{0};
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
    mutable std::mutex telemetryMutex;
    DownloadTelemetry telemetry;
    std::atomic<bool> summaryPresented{false};
    std::string destinationKey;
};

struct PeerReputation {
    u64 successes = 0;
    u64 networkFailures = 0;
    u64 authenticationFailures = 0;
    u64 integrityFailures = 0;
    u64 bytes = 0;
    double transferSeconds = 0.0;
    std::time_t blacklistedUntil = 0;
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

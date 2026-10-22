#pragma once

/// @file peer_stats.hpp
/// Per-peer counters for the show_peers command.

#include "common/encoding.hpp"
#include "common/net/net.hpp"

#include <map>
#include <mutex>
#include <ostream>
#include <string>

/// The outcome of one request to a peer.
enum class TransferResult {
    Success,                 ///< Got a valid, authenticated reply (and a matching hash).
    NetworkFailure,          ///< Couldn't connect, or the connection broke.
    AuthenticationFailure,   ///< Denied, or the reply didn't decrypt or had the wrong shape.
    IntegrityFailure,        ///< A piece arrived but its SHA-1 was wrong.
    Unavailable              ///< The peer accepted the ticket but lacks that piece.
};

/// What happened on every request to every peer: plain counts and measured
/// throughput, no reputation scores. Thread-safe.
class PeerStats {
public:
    /// Records one request.
    /// @param bytes   Payload bytes received (counted on success only).
    /// @param seconds Time the request took (counted on success only).
    void record(const Endpoint &peer, TransferResult result, u64 bytes = 0, double seconds = 0.0);

    /// Prints one line per peer, sorted by address: speed in MiB/s and the
    /// count of each outcome.
    void print(std::ostream &out) const;

private:
    struct Counters {
        u64 successes = 0;
        u64 networkFailures = 0;
        u64 authenticationFailures = 0;
        u64 integrityFailures = 0;
        u64 bytes = 0;          ///< Bytes from successful requests.
        double seconds = 0.0;   ///< Time spent on successful requests.
    };

    mutable std::mutex mutex_;                ///< Guards peers_.
    std::map<std::string, Counters> peers_;   ///< "ip:port" -> counters
};

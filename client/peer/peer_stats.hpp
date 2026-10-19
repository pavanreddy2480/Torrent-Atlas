#pragma once

// What happened on every request to every peer, for the peer_stats command.

#include "common/encoding.hpp"
#include "common/net/net.hpp"

#include <map>
#include <mutex>
#include <ostream>
#include <string>

enum class TransferResult { Success, NetworkFailure, AuthenticationFailure, IntegrityFailure, Unavailable };

class PeerStats {
public:
    void record(const Endpoint &peer, TransferResult result, u64 bytes = 0, double seconds = 0.0);
    void print(std::ostream &out) const;

private:
    struct Counters {
        u64 successes = 0;
        u64 networkFailures = 0;
        u64 authenticationFailures = 0;
        u64 integrityFailures = 0;
        u64 bytes = 0;
        double seconds = 0.0;
    };

    mutable std::mutex mutex_;
    std::map<std::string, Counters> peers_;
};

#include "peer_stats.hpp"

#include <iomanip>

void PeerStats::record(const Endpoint &peer, TransferResult result, u64 bytes, double seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    Counters &counters = peers_[peer.toString()];
    switch (result) {
    case TransferResult::Success:
        ++counters.successes;
        counters.bytes += bytes;
        counters.seconds += seconds;
        break;
    case TransferResult::NetworkFailure: ++counters.networkFailures; break;
    case TransferResult::AuthenticationFailure: ++counters.authenticationFailures; break;
    case TransferResult::IntegrityFailure: ++counters.integrityFailures; break;
    case TransferResult::Unavailable: break;
    }
}

void PeerStats::print(std::ostream &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (peers_.empty()) {
        out << "No peer observations yet\n";
        return;
    }
    for (const auto &[peer, counters] : peers_) {
        double speed = counters.seconds > 0.0 ? counters.bytes / counters.seconds / (1024.0 * 1024.0)
                                              : 0.0;
        out << peer << " speed=" << std::fixed << std::setprecision(1) << speed << "MiB/s"
            << " ok=" << counters.successes << " network=" << counters.networkFailures
            << " auth=" << counters.authenticationFailures
            << " corrupt=" << counters.integrityFailures << '\n';
    }
}

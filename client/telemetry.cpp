#include "telemetry.hpp"

#include "../common/secure_crypto.hpp"

#include <algorithm>
#include <mutex>

u64 elapsedMicroseconds(std::chrono::steady_clock::time_point started) {
    return static_cast<u64>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
}

std::chrono::milliseconds retryDelay(int round) {
    unsigned char random = 0;
    secureRandom(&random, sizeof(random));
    int exponential = 150 * (1 << std::min(round, 4));
    return std::chrono::milliseconds(exponential + random % 101);
}

void recordDownloadFailure(const std::shared_ptr<DownloadStatus> &status,
                           TransferResult result) {
    if (!status || result == TransferResult::Success) return;
    ++status->retries;
    if (result == TransferResult::NetworkFailure) {
        ++status->networkFailures;
    } else if (result == TransferResult::AuthenticationFailure) {
        ++status->authenticationFailures;
    } else if (result == TransferResult::Unavailable) {
        ++status->unavailableResponses;
    }
}

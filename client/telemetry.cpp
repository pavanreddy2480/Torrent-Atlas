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

void addProtocolEvent(const std::shared_ptr<DownloadStatus> &status,
                      const std::string &event) {
    if (!status) return;
    std::lock_guard<std::mutex> lock(status->telemetryMutex);
    status->telemetry.events.push_back(event);
    while (status->telemetry.events.size() > 80)
        status->telemetry.events.pop_front();
}

void sampleDownloadSpeed(const std::shared_ptr<DownloadStatus> &status,
                         bool force) {
    if (!status) return;
    std::lock_guard<std::mutex> lock(status->telemetryMutex);
    auto now = std::chrono::steady_clock::now();
    double seconds =
        std::chrono::duration<double>(now -
                                      status->telemetry.lastSpeedSample)
            .count();
    if (!force && seconds < 0.25) return;
    u64 bytes = status->verifiedBytes.load();
    u64 delta = bytes >= status->telemetry.lastSpeedBytes
                    ? bytes - status->telemetry.lastSpeedBytes
                    : 0;
    status->telemetry.speedHistory.push_back(
        seconds > 0.0 ? static_cast<double>(delta) / seconds /
                            (1024.0 * 1024.0)
                      : 0.0);
    while (status->telemetry.speedHistory.size() > 60)
        status->telemetry.speedHistory.pop_front();
    status->telemetry.lastSpeedBytes = bytes;
    status->telemetry.lastSpeedSample = now;
}

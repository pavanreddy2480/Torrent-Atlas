#pragma once

#include "client_types.hpp"

#include <chrono>
#include <memory>
#include <string>

u64 elapsedMicroseconds(std::chrono::steady_clock::time_point started);
std::chrono::milliseconds retryDelay(int round);
void recordDownloadFailure(const std::shared_ptr<DownloadStatus> &status,
                           TransferResult result);
void addProtocolEvent(const std::shared_ptr<DownloadStatus> &status,
                      const std::string &event);
void sampleDownloadSpeed(const std::shared_ptr<DownloadStatus> &status,
                         bool force = false);

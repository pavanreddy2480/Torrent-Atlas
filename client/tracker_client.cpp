#include "client/tracker_client.hpp"

#include "common/net/secure_channel.hpp"

#include <chrono>
#include <sstream>
#include <thread>

namespace {

bool startsWith(const std::string &text, const std::string &prefix) {
    return text.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

TrackerClient::TrackerClient(ClientConfig config, Endpoint self)
    : config_(std::move(config)), self_(std::move(self)) {}

bool TrackerClient::request(const std::string &command, std::string &response) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::vector<Endpoint> &trackers = config_.trackers;
    std::string message = "C\t" + std::to_string(session_) + "\t" + command;
    bool answered = false;
    for (int attempt = 0; attempt < 12 && !answered; ++attempt) {
        if (!callTracker(trackers[leader_], config_.trackerPublicKey, message, response)) {
            leader_ = (leader_ + 1) % trackers.size();   // down: try the next one
        } else if (startsWith(response, "REDIRECT ")) {
            std::optional<Endpoint> leader =
                Endpoint::parse(response.substr(9, response.find('\t') - 9));
            for (std::size_t i = 0; leader && i < trackers.size(); ++i)
                if (trackers[i] == *leader) leader_ = i;
        } else if (startsWith(response, "ERR no leader elected yet") ||
                   startsWith(response, "ERR leader catching up") ||
                   startsWith(response, "ERR write not committed")) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        } else {
            answered = true;
        }
    }
    if (!answered) {
        response = "ERR tracker cluster unavailable";
        return false;
    }
    // Every reply ends with "\t<session>".
    std::size_t tab = response.rfind('\t');
    u64 session = 0;
    if (tab == std::string::npos || !parseU64(response.substr(tab + 1), session)) return false;
    session_ = session;
    response.resize(tab);
    return true;
}

bool TrackerClient::share(const std::string &group, const std::string &name,
                          const FileMetadata &metadata, std::string &response) {
    return request("upload_file " + group + " " + toHex(name) + " " +
                       std::to_string(metadata.size) + " " + metadata.fullHash + " " +
                       metadata.capability + " " + metadata.pieceHashList() + " " + self_.ip +
                       " " + std::to_string(self_.port),
                   response);
}

bool TrackerClient::locate(const std::string &group, const std::string &name,
                           FileMetadata &metadata, std::vector<Endpoint> &seeders,
                           std::string &error) {
    std::string response;
    if (!request("download_file " + group + " " + toHex(name), response) ||
        !startsWith(response, "META ")) {
        error = response;
        return false;
    }
    // META <size> <SHA-1> <capability> <piece hashes> <ip:port,...>
    std::istringstream input(response);
    std::vector<std::string> fields;
    for (std::string field; input >> field;) fields.push_back(field);
    if (fields.size() == 6) {
        metadata.fullHash = fields[2];
        metadata.capability = fields[3];
        metadata.pieceHashes = FileMetadata::parsePieceHashList(fields[4]);
    }
    if (fields.size() != 6 || !parseU64(fields[1], metadata.size) || !metadata.valid()) {
        error = "ERR invalid tracker metadata";
        return false;
    }
    seeders.clear();
    for (const std::string &text : split(fields[5], ','))
        if (std::optional<Endpoint> seeder = Endpoint::parse(text)) seeders.push_back(*seeder);
    if (seeders.empty()) {
        error = "ERR no valid peer endpoints";
        return false;
    }
    return true;
}

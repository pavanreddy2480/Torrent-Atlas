#include "client/tracker_client.hpp"

#include "common/net/secure_channel.hpp"

#include <sstream>

TrackerClient::TrackerClient(ClientConfig config, Endpoint self, std::string peerKey)
    : config_(std::move(config)), self_(std::move(self)), peerKey_(std::move(peerKey)) {}

bool TrackerClient::request(const std::string &command, std::string &response) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string message = "C\t" + std::to_string(session_) + "\t" + command;
    if (!callTracker(config_.tracker, config_.trackerPublicKey, message, response)) {
        response = "ERR tracker unavailable";
        return false;
    }
    // Every reply ends with "\t<session>".
    std::size_t tab = response.rfind('\t');
    u64 session = 0;
    if (tab == std::string::npos || !parseU64(response.substr(tab + 1), session)) {
        response = "ERR invalid tracker reply";
        return false;
    }
    session_ = session;
    response.resize(tab);
    return true;
}

bool TrackerClient::share(const std::string &group, const std::string &name,
                          const FileMetadata &metadata, std::string &response) {
    return request("upload_file " + group + " " + toHex(name) + " " +
                       std::to_string(metadata.size) + " " + metadata.fullHash + " " +
                       metadata.pieceHashList() + " " + self_.ip + " " +
                       std::to_string(self_.port) + " " + toHex(peerKey_),
                   response);
}

bool TrackerClient::locate(const std::string &group, const std::string &name,
                           FileMetadata &metadata, std::vector<SeederAccess> &seeders,
                           std::string &error) {
    std::string response;
    if (!request("download_file " + group + " " + toHex(name), response) ||
        response.rfind("META ", 0) != 0) {
        error = response;
        return false;
    }
    // META <size> <SHA-1> <piece hashes> <seeder>,<seeder>...
    std::istringstream input(response);
    std::vector<std::string> fields;
    for (std::string field; input >> field;) fields.push_back(field);
    if (fields.size() == 5) {
        metadata.fullHash = fields[2];
        metadata.pieceHashes = FileMetadata::parsePieceHashList(fields[3]);
    }
    if (fields.size() != 5 || !parseU64(fields[1], metadata.size) || !metadata.valid()) {
        error = "ERR invalid tracker metadata";
        return false;
    }
    seeders.clear();
    for (const std::string &text : split(fields[4], ','))
        if (std::optional<SeederAccess> seeder = SeederAccess::decode(text))
            seeders.push_back(*seeder);
    if (seeders.empty()) {
        error = "ERR no valid peer endpoints";
        return false;
    }
    return true;
}

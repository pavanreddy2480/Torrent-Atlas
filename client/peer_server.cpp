#include "peer_server.hpp"

#include "peer_protocol.hpp"
#include "piece_file.hpp"

#include "../common/freshness.hpp"

using peer_protocol::error;

PeerServer::PeerServer(const SharedFiles &files)
    : files_(files), server_([this](Socket socket) {
          socket.setTimeout(8);
          std::string request;
          if (socket.receiveFrame(request)) socket.sendFrame(respond(request));
      }) {}

bool PeerServer::start(const Endpoint &endpoint) {
    if (!server_.listen(endpoint)) return false;
    thread_ = std::thread([this] { server_.serve(); });
    return true;
}

void PeerServer::stop() {
    server_.stop();
    if (thread_.joinable()) thread_.join();
}

std::string PeerServer::respond(const std::string &request) const {
    std::vector<std::string> fields = split(request, '|');
    if (fields.size() != 6 || fields[0] != peer_protocol::REQUEST) return error("malformed");
    std::string group, name;
    if (!fromHex(fields[1], group) || !fromHex(fields[2], name) || group.empty() || name.empty())
        return error("encoding");
    std::optional<LocalFile> file = files_.find(group, name);
    if (!file) return error("unauthorized");

    std::string key, plain;
    crypto::AesGcmMessage received;
    if (!fromHex(file->metadata.capability, key) || key.size() != 32 ||
        !peer_protocol::decode(fields, 3, received))
        return error("encoding");
    std::string aad = peer_protocol::requestAad(fields[1], fields[2]);
    if (!crypto::decrypt(key, aad, received, plain)) return error("aead");

    std::vector<std::string> parts = split(plain, '\n');   // operation, piece, timestamp
    u64 piece = 0;
    if (parts.size() != 3) return error("request");
    if (!isFreshTimestamp(parts[2])) return error("stale");
    if (!parseU64(parts[1], piece)) return error("piece");

    std::string reply;
    if (parts[0] == "BITMAP") {
        for (bool available : file->available) reply.push_back(available ? 1 : 0);
    } else if (parts[0] == "GET" && piece < file->available.size() && file->available[piece]) {
        PieceFile data = PieceFile::openForReading(file->path);
        if (!data) return error("open");
        if (!data.read(piece, file->metadata.pieceLength(piece), reply)) return error("read");
    } else {
        return error("unauthorized");
    }
    crypto::AesGcmMessage sent;
    if (!crypto::encrypt(key, peer_protocol::replyAad(aad, fields[3]), reply, sent))
        return error("encrypt");
    return peer_protocol::encode(peer_protocol::REPLY, sent);
}

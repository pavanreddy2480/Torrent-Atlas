#include "client/peer/peer_server.hpp"

#include "client/peer/peer_protocol.hpp"
#include "client/storage/piece_file.hpp"

#include "common/net/freshness.hpp"
#include "common/peer_ticket.hpp"

using peer_protocol::DENIED;
using peer_protocol::UNAVAILABLE;

PeerServer::PeerServer(const SharedFiles &files, std::string peerKey)
    : files_(files), peerKey_(std::move(peerKey)), server_([this](Socket socket) {
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

// Every check that fails before the request is known to be genuine returns
// the same DENIED, and the shared-file lookup comes last, so a caller without
// a valid ticket cannot tell which files this peer has.
std::string PeerServer::respond(const std::string &request) const {
    std::vector<std::string> fields = split(request, '|');
    if (fields.size() != 5 || fields[0] != peer_protocol::REQUEST) return DENIED;
    std::optional<PeerTicket> ticket = PeerTicket::decode(fields[1]);
    if (!ticket || ticket->expired(unixSeconds())) return DENIED;

    std::string key = ticket->key(peerKey_), plain;
    std::string aad = peer_protocol::requestAad(fields[1]);
    crypto::AesGcmMessage received;
    if (!peer_protocol::decode(fields, 2, received) || !crypto::decrypt(key, aad, received, plain))
        return DENIED;
    std::vector<std::string> parts = split(plain, '\n');   // operation, piece, timestamp
    u64 piece = 0;
    if (parts.size() != 3 || !isFreshTimestamp(parts[2]) || !parseU64(parts[1], piece))
        return DENIED;
    std::optional<LocalFile> file = files_.find(ticket->group, ticket->file);
    if (!file) return DENIED;

    std::string reply;
    if (parts[0] == "BITMAP") {
        for (bool available : file->available) reply.push_back(available ? 1 : 0);
    } else if (parts[0] == "GET" && piece < file->available.size() && file->available[piece]) {
        PieceFile data = PieceFile::openForReading(file->path);
        if (!data || !data.read(piece, file->metadata.pieceLength(piece), reply))
            return UNAVAILABLE;
    } else {
        return UNAVAILABLE;
    }
    crypto::AesGcmMessage sent;
    if (!crypto::encrypt(key, peer_protocol::replyAad(aad, fields[2]), reply, sent))
        return UNAVAILABLE;
    return peer_protocol::encode(peer_protocol::REPLY, sent);
}

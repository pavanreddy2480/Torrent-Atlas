#include "client/peer/peer_client.hpp"

#include "client/peer/peer_protocol.hpp"

TransferResult PeerClient::request(const SeederAccess &seeder, const std::string &operation,
                                   std::size_t piece, std::string &reply) const {
    std::string frame, nonce, response;
    if (!peer_protocol::makeRequest(seeder.ticket, seeder.key, operation, piece, frame, nonce))
        return TransferResult::AuthenticationFailure;
    Socket socket = Socket::connect(seeder.endpoint);
    if (!socket || !socket.sendFrame(frame) || !socket.receiveFrame(response))
        return TransferResult::NetworkFailure;
    if (response == peer_protocol::UNAVAILABLE) return TransferResult::Unavailable;
    if (!peer_protocol::openReply(seeder.ticket, seeder.key, nonce, response, reply))
        return TransferResult::AuthenticationFailure;
    return TransferResult::Success;
}

TransferResult PeerClient::fetchBitmap(const SeederAccess &seeder, std::size_t pieceCount,
                                       std::vector<bool> &bitmap) const {
    std::string reply;
    TransferResult result = request(seeder, "BITMAP", 0, reply);
    if (result == TransferResult::Success && reply.size() != pieceCount)
        return TransferResult::AuthenticationFailure;
    if (result != TransferResult::Success) return result;
    bitmap.clear();
    for (char piece : reply) bitmap.push_back(piece != 0);
    return result;
}

TransferResult PeerClient::fetchPiece(const SeederAccess &seeder, std::size_t index,
                                      const std::string &expectedHash, std::string &data) const {
    TransferResult result = request(seeder, "GET", index, data);
    if (result == TransferResult::Success && crypto::sha1Hex(data) != expectedHash)
        return TransferResult::IntegrityFailure;
    return result;
}

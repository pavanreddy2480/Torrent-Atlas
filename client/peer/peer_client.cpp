#include "client/peer/peer_client.hpp"

#include "client/peer/peer_protocol.hpp"

#include <chrono>

TransferResult PeerClient::request(const SeederAccess &seeder, const std::string &operation,
                                   std::size_t piece, std::string &reply, double &seconds) {
    auto started = std::chrono::steady_clock::now();
    std::string frame, nonce, response;
    if (!peer_protocol::makeRequest(seeder.ticket, seeder.key, operation, piece, frame, nonce))
        return TransferResult::AuthenticationFailure;
    Socket socket = Socket::connect(seeder.endpoint);
    if (!socket || !socket.sendFrame(frame) || !socket.receiveFrame(response))
        return TransferResult::NetworkFailure;
    seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    if (response == peer_protocol::UNAVAILABLE) return TransferResult::Unavailable;
    if (!peer_protocol::openReply(seeder.ticket, seeder.key, nonce, response, reply))
        return TransferResult::AuthenticationFailure;
    return TransferResult::Success;
}

TransferResult PeerClient::fetchBitmap(const SeederAccess &seeder, std::size_t pieceCount,
                                       std::vector<bool> &bitmap) {
    std::string reply;
    double seconds = 0.0;
    TransferResult result = request(seeder, "BITMAP", 0, reply, seconds);
    if (result == TransferResult::Success && reply.size() != pieceCount)
        result = TransferResult::AuthenticationFailure;
    stats_.record(seeder.endpoint, result, 0, seconds);
    if (result != TransferResult::Success) return result;
    bitmap.clear();
    for (char piece : reply) bitmap.push_back(piece != 0);
    return result;
}

TransferResult PeerClient::fetchPiece(const SeederAccess &seeder, std::size_t index,
                                      const std::string &expectedHash, std::string &data) {
    double seconds = 0.0;
    TransferResult result = request(seeder, "GET", index, data, seconds);
    if (result == TransferResult::Success && crypto::sha1Hex(data) != expectedHash)
        result = TransferResult::IntegrityFailure;
    stats_.record(seeder.endpoint, result, data.size(), seconds);
    return result;
}

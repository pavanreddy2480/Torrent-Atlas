#include "client/peer/peer_client.hpp"

#include "client/peer/peer_protocol.hpp"

#include "common/net/freshness.hpp"

#include <chrono>

PeerClient::PeerClient(std::string group, std::string name, std::string capability,
                       PeerStats &stats)
    : group_(std::move(group)), name_(std::move(name)), capability_(std::move(capability)),
      stats_(stats) {}

TransferResult PeerClient::request(const Endpoint &peer, const std::string &operation,
                                   std::size_t piece, std::string &reply, double &seconds) {
    auto started = std::chrono::steady_clock::now();
    Socket socket = Socket::connect(peer);
    if (!socket) return TransferResult::NetworkFailure;
    std::string key;
    if (!fromHex(capability_, key) || key.size() != 32)
        return TransferResult::AuthenticationFailure;

    std::string aad = peer_protocol::requestAad(toHex(group_), toHex(name_));
    std::string plain = operation + "\n" + std::to_string(piece) + "\n" + std::to_string(unixSeconds());
    crypto::AesGcmMessage sent;
    std::string response;
    if (!crypto::encrypt(key, aad, plain, sent) ||
        !socket.sendFrame(peer_protocol::encode(aad, sent)) || !socket.receiveFrame(response))
        return TransferResult::NetworkFailure;
    seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

    std::vector<std::string> fields = split(response, '|');
    if (fields.size() >= 2 && fields[0] == peer_protocol::ERROR)
        return fields[1] == "unauthorized" || fields[1] == "aead"
                   ? TransferResult::AuthenticationFailure
                   : TransferResult::Unavailable;
    crypto::AesGcmMessage received;
    if (fields.size() != 4 || fields[0] != peer_protocol::REPLY ||
        !peer_protocol::decode(fields, 1, received) ||
        !crypto::decrypt(key, peer_protocol::replyAad(aad, toHex(sent.nonce)), received, reply))
        return TransferResult::AuthenticationFailure;
    return TransferResult::Success;
}

TransferResult PeerClient::fetchBitmap(const Endpoint &peer, std::size_t pieceCount,
                                       std::vector<bool> &bitmap) {
    std::string reply;
    double seconds = 0.0;
    TransferResult result = request(peer, "BITMAP", 0, reply, seconds);
    if (result == TransferResult::Success && reply.size() != pieceCount)
        result = TransferResult::AuthenticationFailure;
    stats_.record(peer, result, 0, seconds);
    if (result != TransferResult::Success) return result;
    bitmap.clear();
    for (char piece : reply) bitmap.push_back(piece != 0);
    return result;
}

TransferResult PeerClient::fetchPiece(const Endpoint &peer, std::size_t index,
                                      const std::string &expectedHash, std::string &data) {
    double seconds = 0.0;
    TransferResult result = request(peer, "GET", index, data, seconds);
    if (result == TransferResult::Success && crypto::sha1Hex(data) != expectedHash)
        result = TransferResult::IntegrityFailure;
    stats_.record(peer, result, data.size(), seconds);
    return result;
}

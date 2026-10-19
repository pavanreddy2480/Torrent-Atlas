#include "secure_channel.hpp"

#include "crypto.hpp"
#include "encoding.hpp"
#include "freshness.hpp"

namespace {

// Parses "HELLO|<x25519 public>|<nonce>|<timestamp>[|signature]".
bool parseHello(const std::vector<std::string> &fields, std::size_t expectedFields,
                std::string &publicKey) {
    std::string nonce;
    return fields.size() == expectedFields && fields[0] == "HELLO" &&
           fromHex(fields[1], publicKey) && publicKey.size() == 32 &&
           fromHex(fields[2], nonce) && nonce.size() == 16 && isFreshTimestamp(fields[3]);
}

std::string helloFields(const crypto::KeyPair &ephemeral, const std::string &nonce) {
    return toHex(ephemeral.publicKey) + "|" + toHex(nonce) + "|" + std::to_string(unixSeconds());
}

std::string transcript(const std::string &clientHello, const std::string &serverFields) {
    return "torrent-handshake-v1|" + clientHello + "|" + serverFields;
}

std::string sessionKey(crypto::KeyPair &ephemeral, const std::string &peerPublic,
                       const std::string &transcript) {
    std::string shared = crypto::x25519SharedSecret(ephemeral.privateKey, peerPublic);
    crypto::secureErase(ephemeral.privateKey);
    if (shared.empty()) return {};
    std::string key = crypto::sha256(shared + transcript);
    crypto::secureErase(shared);
    return key;
}

}  // namespace

SecureChannel::SecureChannel(Socket socket, std::string key, bool client)
    : socket_(std::move(socket)), key_(std::move(key)),
      sendLabel_(client ? "client->tracker" : "tracker->client"),
      receiveLabel_(client ? "tracker->client" : "client->tracker") {}

SecureChannel::~SecureChannel() { crypto::secureErase(key_); }

std::optional<SecureChannel> SecureChannel::connect(Socket socket,
                                                    const std::string &trackerPublicKey) {
    std::optional<crypto::KeyPair> ephemeral = crypto::x25519KeyPair();
    std::string nonce = crypto::randomBytes(16);
    if (!ephemeral || nonce.size() != 16) return std::nullopt;
    std::string hello = "HELLO|" + helloFields(*ephemeral, nonce);
    std::string reply, serverPublic, signature;
    if (!socket.sendFrame(hello) || !socket.receiveFrame(reply)) return std::nullopt;
    std::vector<std::string> fields = split(reply, '|');
    if (!parseHello(fields, 5, serverPublic) || !fromHex(fields[4], signature))
        return std::nullopt;
    std::string signedText = transcript(hello, fields[1] + "|" + fields[2] + "|" + fields[3]);
    if (!crypto::ed25519Verify(trackerPublicKey, signedText, signature)) return std::nullopt;
    std::string key = sessionKey(*ephemeral, serverPublic, signedText);
    if (key.size() != 32) return std::nullopt;
    return SecureChannel(std::move(socket), std::move(key), true);
}

std::optional<SecureChannel> SecureChannel::accept(Socket socket,
                                                   const std::string &identityPrivateKey) {
    std::string hello, clientPublic;
    if (!socket.receiveFrame(hello) || !parseHello(split(hello, '|'), 4, clientPublic))
        return std::nullopt;
    std::optional<crypto::KeyPair> ephemeral = crypto::x25519KeyPair();
    std::string nonce = crypto::randomBytes(16);
    if (!ephemeral || nonce.size() != 16) return std::nullopt;
    std::string serverFields = helloFields(*ephemeral, nonce);
    std::string signedText = transcript(hello, serverFields);
    std::string signature = crypto::ed25519Sign(identityPrivateKey, signedText);
    if (signature.empty() ||
        !socket.sendFrame("HELLO|" + serverFields + "|" + toHex(signature)))
        return std::nullopt;
    std::string key = sessionKey(*ephemeral, clientPublic, signedText);
    if (key.size() != 32) return std::nullopt;
    return SecureChannel(std::move(socket), std::move(key), false);
}

std::string SecureChannel::seal(const std::string &plain) const {
    crypto::AesGcmMessage message;
    if (!crypto::encrypt(key_, sendLabel_, plain, message)) return {};
    return message.nonce + message.tag + message.ciphertext;
}

bool SecureChannel::receive(std::string &plain) {
    std::string frame;
    if (!socket_.receiveFrame(frame) || frame.size() < 28) return false;
    crypto::AesGcmMessage message{frame.substr(0, 12), frame.substr(28), frame.substr(12, 16)};
    return crypto::decrypt(key_, receiveLabel_, message, plain);
}

bool callTracker(const Endpoint &tracker, const std::string &trackerPublicKey,
                 const std::string &request, std::string &response, int timeoutSeconds) {
    Socket socket = Socket::connect(tracker, timeoutSeconds);
    if (!socket) return false;
    std::optional<SecureChannel> channel = SecureChannel::connect(std::move(socket), trackerPublicKey);
    return channel && channel->send(request) && channel->receive(response);
}

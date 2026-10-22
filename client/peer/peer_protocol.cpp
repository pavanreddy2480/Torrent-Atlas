#include "client/peer/peer_protocol.hpp"

#include "common/encoding.hpp"
#include "common/net/freshness.hpp"

namespace peer_protocol {

std::string encode(const std::string &prefix, const crypto::AesGcmMessage &message) {
    return prefix + "|" + toHex(message.nonce) + "|" + toHex(message.ciphertext) + "|" +
           toHex(message.tag);
}

bool decode(const std::vector<std::string> &fields, std::size_t first,
            crypto::AesGcmMessage &message) {
    return fields.size() >= first + 3 && fromHex(fields[first], message.nonce) &&
           fromHex(fields[first + 1], message.ciphertext) && fromHex(fields[first + 2], message.tag);
}

bool makeRequest(const std::string &ticket, const std::string &key, const std::string &operation,
                 std::size_t piece, std::string &frame, std::string &nonce) {
    std::string aad = requestAad(ticket);
    std::string plain = operation + "\n" + std::to_string(piece) + "\n" + std::to_string(unixSeconds());
    crypto::AesGcmMessage message;
    if (!crypto::encrypt(key, aad, plain, message)) return false;
    frame = encode(aad, message);
    nonce = message.nonce;
    return true;
}

bool openReply(const std::string &ticket, const std::string &key, const std::string &nonce,
               const std::string &frame, std::string &plain) {
    std::vector<std::string> fields = split(frame, '|');
    crypto::AesGcmMessage message;
    return fields.size() == 4 && fields[0] == REPLY && decode(fields, 1, message) &&
           crypto::decrypt(key, replyAad(requestAad(ticket), toHex(nonce)), message, plain);
}

}  // namespace peer_protocol

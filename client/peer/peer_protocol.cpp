#include "client/peer/peer_protocol.hpp"

#include "common/encoding.hpp"

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

}  // namespace peer_protocol

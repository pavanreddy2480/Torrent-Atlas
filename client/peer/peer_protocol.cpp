#include "client/peer/peer_protocol.hpp"

#include "common/ablation.hpp"
#include "common/encoding.hpp"

#include <openssl/evp.h>
#include "common/net/freshness.hpp"

namespace peer_protocol {

namespace {

// Ablation helpers: the wire encoding is hex unless TORRENT_ABL_ENCODING=base64.
std::string toWire(const std::string &bytes) {
    if (!ablation::base64()) return toHex(bytes);
    std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    int length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
                                 reinterpret_cast<const unsigned char *>(bytes.data()),
                                 static_cast<int>(bytes.size()));
    out.resize(static_cast<std::size_t>(length));
    return out;
}

bool fromWire(const std::string &text, std::string &bytes) {
    if (!ablation::base64()) return fromHex(text, bytes);
    if (text.size() % 4 != 0) return false;
    bytes.assign(text.size() / 4 * 3, '\0');
    int length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(&bytes[0]),
                                 reinterpret_cast<const unsigned char *>(text.data()),
                                 static_cast<int>(text.size()));
    if (length < 0) return false;
    std::size_t padding = text.size() >= 2 ? (text.back() == '=') + (text[text.size() - 2] == '=') : 0;
    bytes.resize(static_cast<std::size_t>(length) - padding);
    return true;
}

}  // namespace

bool seal(const std::string &key, const std::string &aad, const std::string &plain,
          crypto::AesGcmMessage &message) {
    if (ablation::encrypt()) return crypto::encrypt(key, aad, plain, message);
    message = {std::string(12, 'n'), plain, std::string(16, 't')};   // ablation: no encryption
    return true;
}

bool unseal(const std::string &key, const std::string &aad, const crypto::AesGcmMessage &message,
            std::string &plain) {
    if (ablation::encrypt()) return crypto::decrypt(key, aad, message, plain);
    plain = message.ciphertext;
    return true;
}

std::string encode(const std::string &prefix, const crypto::AesGcmMessage &message) {
    return prefix + "|" + toWire(message.nonce) + "|" + toWire(message.ciphertext) + "|" +
           toWire(message.tag);
}

bool decode(const std::vector<std::string> &fields, std::size_t first,
            crypto::AesGcmMessage &message) {
    return fields.size() >= first + 3 && fromWire(fields[first], message.nonce) &&
           fromWire(fields[first + 1], message.ciphertext) && fromWire(fields[first + 2], message.tag);
}

bool makeRequest(const std::string &ticket, const std::string &key, const std::string &operation,
                 std::size_t piece, std::string &frame, std::string &nonce) {
    std::string aad = requestAad(ticket);
    std::string plain = operation + "\n" + std::to_string(piece) + "\n" + std::to_string(unixSeconds());
    crypto::AesGcmMessage message;
    if (!seal(key, aad, plain, message)) return false;
    frame = encode(aad, message);
    nonce = message.nonce;
    return true;
}

bool openReply(const std::string &ticket, const std::string &key, const std::string &nonce,
               const std::string &frame, std::string &plain) {
    std::vector<std::string> fields = split(frame, '|');
    crypto::AesGcmMessage message;
    return fields.size() == 4 && fields[0] == REPLY && decode(fields, 1, message) &&
           unseal(key, replyAad(requestAad(ticket), toHex(nonce)), message, plain);
}

}  // namespace peer_protocol

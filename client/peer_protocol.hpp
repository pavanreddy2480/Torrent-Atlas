#pragma once

// Peer <-> peer piece transfer, one request per connection. Everything is
// AES-256-GCM under the file's capability key, which only group members get
// from the tracker. Fields are hex unless noted.
//
//   request  "21|<group>|<file>|<nonce>|<ciphertext>|<tag>"
//            plaintext "<BITMAP or GET>\n<piece index>\n<unix seconds>"
//            AAD "21|<group>|<file>"
//   reply    "30|<nonce>|<ciphertext>|<tag>"
//            plaintext: the piece bytes, or one byte per piece (1 = have it)
//            AAD "30|" + request AAD + "|" + request nonce
//   error    "60|<reason>" (plain text)
//
// The timestamp rejects old requests replayed later; binding the reply to the
// request nonce stops a reply from being reused for another request.

#include "../common/crypto.hpp"

#include <string>
#include <vector>

namespace peer_protocol {

inline const std::string REQUEST = "21";
inline const std::string REPLY = "30";
inline const std::string ERROR = "60";

inline std::string requestAad(const std::string &hexGroup, const std::string &hexName) {
    return REQUEST + "|" + hexGroup + "|" + hexName;
}

inline std::string replyAad(const std::string &requestAad, const std::string &hexRequestNonce) {
    return REPLY + "|" + requestAad + "|" + hexRequestNonce;
}

inline std::string error(const std::string &reason) { return ERROR + "|" + reason; }

// "<prefix>|<nonce>|<ciphertext>|<tag>"
std::string encode(const std::string &prefix, const crypto::AesGcmMessage &message);
// Reads nonce, ciphertext and tag from fields[first..first+2].
bool decode(const std::vector<std::string> &fields, std::size_t first,
            crypto::AesGcmMessage &message);

}  // namespace peer_protocol

#pragma once

// Peer <-> peer piece transfer, one request per connection. A downloader may
// only ask with a ticket the tracker issued for it (see peer_ticket.hpp), and
// everything is AES-256-GCM under that ticket's key. Fields are hex unless
// noted.
//
//   request  "21|<ticket>|<nonce>|<ciphertext>|<tag>"     (ticket as text)
//            plaintext "<BITMAP or GET>\n<piece index>\n<unix seconds>"
//            AAD "21|<ticket>"
//   reply    "30|<nonce>|<ciphertext>|<tag>"
//            plaintext: the piece bytes, or one byte per piece (1 = have it)
//            AAD "30|" + request AAD + "|" + request nonce
//   error    "60|denied"       any request that does not fully check out:
//                              malformed, bad or expired ticket, wrong key,
//                              stale, or for a file this peer is not sharing.
//                              One reply for all of them, so a stranger
//                              learns nothing, not even which files exist.
//            "60|unavailable"  a valid request for a piece this peer lacks
//
// The timestamp rejects old requests replayed later; binding the reply to the
// request nonce stops a reply from being reused for another request.

#include "common/crypto/crypto.hpp"

#include <string>
#include <vector>

namespace peer_protocol {

inline const std::string REQUEST = "21";
inline const std::string REPLY = "30";
inline const std::string ERROR = "60";
inline const std::string DENIED = ERROR + "|denied";
inline const std::string UNAVAILABLE = ERROR + "|unavailable";

inline std::string requestAad(const std::string &ticket) { return REQUEST + "|" + ticket; }

inline std::string replyAad(const std::string &requestAad, const std::string &hexRequestNonce) {
    return REPLY + "|" + requestAad + "|" + hexRequestNonce;
}

// "<prefix>|<nonce>|<ciphertext>|<tag>"
std::string encode(const std::string &prefix, const crypto::AesGcmMessage &message);
// Reads nonce, ciphertext and tag from fields[first..first+2].
bool decode(const std::vector<std::string> &fields, std::size_t first,
            crypto::AesGcmMessage &message);

// Downloader side: the request frame for one operation, and the reply's
// plaintext. nonce links the two.
bool makeRequest(const std::string &ticket, const std::string &key, const std::string &operation,
                 std::size_t piece, std::string &frame, std::string &nonce);
bool openReply(const std::string &ticket, const std::string &key, const std::string &nonce,
               const std::string &frame, std::string &plain);

}  // namespace peer_protocol

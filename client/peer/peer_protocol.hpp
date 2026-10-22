#pragma once

/// @file peer_protocol.hpp
/// Peer <-> peer piece transfer, one request per connection. A downloader may
/// only ask with a ticket the tracker issued for it (see peer_ticket.hpp), and
/// everything is AES-256-GCM under that ticket's key. Fields are hex unless
/// noted.
///
///   request  "21|<ticket>|<nonce>|<ciphertext>|<tag>"     (ticket as text)
///            plaintext "<BITMAP or GET>\n<piece index>\n<unix seconds>"
///            AAD "21|<ticket>"
///   reply    "30|<nonce>|<ciphertext>|<tag>"
///            plaintext: the piece bytes, or one byte per piece (1 = have it)
///            AAD "30|" + request AAD + "|" + request nonce
///   error    "60|denied"       any request that does not fully check out:
///                              malformed, bad or expired ticket, wrong key,
///                              stale, or for a file this peer is not sharing.
///                              One reply for all of them, so a stranger
///                              learns nothing, not even which files exist.
///            "60|unavailable"  a valid request for a piece this peer lacks
///
/// The timestamp rejects old requests replayed later; binding the reply to the
/// request nonce stops a reply from being reused for another request.

#include "common/crypto/crypto.hpp"

#include <string>
#include <vector>

namespace peer_protocol {

inline const std::string REQUEST = "21";   ///< Prefix of a request frame.
inline const std::string REPLY = "30";     ///< Prefix of a successful reply.
inline const std::string ERROR = "60";     ///< Prefix of an error reply.
/// The one reply to every request that doesn't fully check out.
inline const std::string DENIED = ERROR + "|denied";
/// The reply to a valid request for a piece this peer can't serve.
inline const std::string UNAVAILABLE = ERROR + "|unavailable";

/// @return The authenticated data for a request carrying ticket.
inline std::string requestAad(const std::string &ticket) { return REQUEST + "|" + ticket; }

/// @return The authenticated data for the reply to a request; binding the
///         request nonce means a reply can't be replayed for another request.
inline std::string replyAad(const std::string &requestAad, const std::string &hexRequestNonce) {
    return REPLY + "|" + requestAad + "|" + hexRequestNonce;
}

/// Serializes an encrypted message as "<prefix>|<nonce>|<ciphertext>|<tag>",
/// each part hex.
std::string encode(const std::string &prefix, const crypto::AesGcmMessage &message);
/// Reads nonce, ciphertext and tag from hex fields[first .. first+2].
/// @return false if there are too few fields or any isn't hex.
bool decode(const std::vector<std::string> &fields, std::size_t first,
            crypto::AesGcmMessage &message);

/// Downloader side: builds the encrypted request frame for one operation.
/// @param ticket    The ticket text from SeederAccess.
/// @param key       The ticket's 32-byte key.
/// @param operation "BITMAP" or "GET".
/// @param piece     Piece index (ignored by the seeder for BITMAP).
/// @param frame     Receives the frame to send.
/// @param nonce     Receives the request nonce; pass it to openReply().
/// @return false if encryption failed.
bool makeRequest(const std::string &ticket, const std::string &key, const std::string &operation,
                 std::size_t piece, std::string &frame, std::string &nonce);
/// Downloader side: checks and decrypts the seeder's reply.
/// @param nonce The nonce makeRequest() returned for this request.
/// @param plain Receives the piece bytes or bitmap.
/// @return false for an error reply, a malformed frame, or one that doesn't
///         authenticate under this ticket, key and nonce.
bool openReply(const std::string &ticket, const std::string &key, const std::string &nonce,
               const std::string &frame, std::string &plain);

}  // namespace peer_protocol

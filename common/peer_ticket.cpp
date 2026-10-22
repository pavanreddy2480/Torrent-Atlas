#include "common/peer_ticket.hpp"

#include "common/crypto/crypto.hpp"
#include "common/encoding.hpp"

std::string PeerTicket::encode() const {
    return toHex(user) + "." + toHex(group) + "." + toHex(file) + "." + std::to_string(expires);
}

std::optional<PeerTicket> PeerTicket::decode(const std::string &text) {
    std::vector<std::string> fields = split(text, '.');
    PeerTicket ticket;
    u64 expires = 0;
    if (fields.size() != 4 || !fromHex(fields[0], ticket.user) || !fromHex(fields[1], ticket.group) ||
        !fromHex(fields[2], ticket.file) || ticket.user.empty() || ticket.group.empty() ||
        ticket.file.empty() || !parseU64(fields[3], expires) || expires > 1ULL << 62)
        return std::nullopt;
    ticket.expires = static_cast<long long>(expires);
    return ticket;
}

std::string PeerTicket::key(const std::string &peerKey) const {
    return crypto::hmacSha256(peerKey, "torrent-peer-ticket-v1|" + encode());
}

std::string SeederAccess::encode() const {
    return endpoint.toString() + "/" + ticket + "/" + toHex(key);
}

std::optional<SeederAccess> SeederAccess::decode(const std::string &text) {
    std::vector<std::string> fields = split(text, '/');
    SeederAccess access;
    std::optional<Endpoint> endpoint;
    if (fields.size() != 3 || !(endpoint = Endpoint::parse(fields[0])) ||
        !PeerTicket::decode(fields[1]) || !fromHex(fields[2], access.key) || access.key.size() != 32)
        return std::nullopt;
    access.endpoint = *endpoint;
    access.ticket = fields[1];
    return access;
}

long long SeederAccess::expires() const {
    std::optional<PeerTicket> decoded = PeerTicket::decode(ticket);
    return decoded ? decoded->expires : 0;
}

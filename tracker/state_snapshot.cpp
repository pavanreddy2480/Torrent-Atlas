// TrackerState snapshots: one record per line, every name hex-encoded.
//   U <user> <stored password>
//   S <session> <user>
//   T <user> <failures> <locked until>
//   G <group> <owner>
//   M <group> <member>            R <group> <pending user>
//   F <group> <file> <size> <SHA-1> <capability> <piece hashes>
//   D <group> <file> <seeder user> <ip> <port>
// std::map keeps every collection sorted, so equal states give equal text.

#include "tracker_state.hpp"

#include <sstream>

std::string TrackerState::serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream out;
    for (const auto &user : data_.users)
        out << "U " << toHex(user.first) << ' ' << toHex(user.second) << '\n';
    for (const auto &session : data_.sessions)
        out << "S " << session.first << ' ' << toHex(session.second) << '\n';
    for (const auto &throttle : data_.throttles)
        out << "T " << toHex(throttle.first) << ' ' << throttle.second.failures << ' '
            << throttle.second.lockedUntil << '\n';
    for (const auto &[groupName, group] : data_.groups) {
        std::string g = toHex(groupName);
        out << "G " << g << ' ' << toHex(group.owner) << '\n';
        for (const std::string &member : group.members) out << "M " << g << ' ' << toHex(member) << '\n';
        for (const std::string &user : group.pending) out << "R " << g << ' ' << toHex(user) << '\n';
        for (const auto &[fileName, file] : group.files) {
            std::string f = toHex(fileName);
            const FileMetadata &meta = file.metadata;
            out << "F " << g << ' ' << f << ' ' << meta.size << ' ' << meta.fullHash << ' '
                << meta.capability << ' ' << meta.pieceHashList() << '\n';
            for (const auto &[user, endpoint] : file.seeders)
                out << "D " << g << ' ' << f << ' ' << toHex(user) << ' ' << toHex(endpoint.ip)
                    << ' ' << endpoint.port << '\n';
        }
    }
    return out.str();
}

namespace {

// Decodes fields[first..] as non-empty hex names.
bool decodeNames(const std::vector<std::string> &fields, std::size_t first, std::size_t count,
                 std::vector<std::string> &names) {
    names.assign(count, "");
    for (std::size_t i = 0; i < count; ++i)
        if (!fromHex(fields[first + i], names[i]) || names[i].empty()) return false;
    return true;
}

}  // namespace

bool TrackerState::restore(const std::string &snapshot) {
    static const std::map<char, std::size_t> fieldCounts = {
        {'U', 3}, {'S', 3}, {'T', 4}, {'G', 3}, {'M', 3}, {'R', 3}, {'F', 7}, {'D', 6}};
    Data data;
    std::istringstream input(snapshot);
    for (std::string line; std::getline(input, line);) {
        if (line.empty()) continue;
        std::vector<std::string> fields = split(line, ' ');
        auto expected = fieldCounts.find(line[0]);
        if (fields[0].size() != 1 || expected == fieldCounts.end() ||
            fields.size() != expected->second)
            return false;
        std::vector<std::string> names;
        u64 a = 0, b = 0;
        switch (line[0]) {
        case 'U':
            if (!decodeNames(fields, 1, 2, names)) return false;
            data.users[names[0]] = names[1];
            break;
        case 'S':
            if (!parseU64(fields[1], a) || a == 0 || !decodeNames(fields, 2, 1, names)) return false;
            data.sessions[a] = names[0];
            break;
        case 'T':
            if (!decodeNames(fields, 1, 1, names) || !parseU64(fields[2], a) ||
                !parseU64(fields[3], b))
                return false;
            data.throttles[names[0]] = {a, static_cast<long long>(b)};
            break;
        case 'G':
            if (!decodeNames(fields, 1, 2, names)) return false;
            data.groups[names[0]].owner = names[1];
            break;
        case 'M':
        case 'R':
            if (!decodeNames(fields, 1, 2, names)) return false;
            (line[0] == 'M' ? data.groups[names[0]].members : data.groups[names[0]].pending)
                .insert(names[1]);
            break;
        case 'F': {
            FileMetadata meta;
            meta.fullHash = fields[4];
            meta.capability = fields[5];
            meta.pieceHashes = FileMetadata::parsePieceHashList(fields[6]);
            if (!decodeNames(fields, 1, 2, names) || !parseU64(fields[3], meta.size) ||
                !meta.valid())
                return false;
            data.groups[names[0]].files[names[1]].metadata = meta;
            break;
        }
        case 'D': {
            std::string ip;
            std::optional<Endpoint> endpoint;
            if (!decodeNames(fields, 1, 3, names) || !fromHex(fields[4], ip) ||
                !(endpoint = Endpoint::parse(ip + ":" + fields[5])))
                return false;
            data.groups[names[0]].files[names[1]].seeders[names[2]] = *endpoint;
            break;
        }
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    data_ = std::move(data);
    return true;
}

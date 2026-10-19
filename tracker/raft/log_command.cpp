#include "tracker/raft/log_command.hpp"

std::string LogCommand::encode() const {
    return std::to_string(session) + "\t" + toHex(context.salt) + "\t" +
           std::to_string(context.newSession) + "\t" + std::to_string(context.now) + "\t" + command;
}

std::optional<LogCommand> LogCommand::decode(const std::string &entry) {
    std::vector<std::string> fields = split(entry, '\t');
    LogCommand decoded;
    u64 now = 0;
    if (fields.size() < 5 || !parseU64(fields[0], decoded.session) ||
        !fromHex(fields[1], decoded.context.salt) ||
        !parseU64(fields[2], decoded.context.newSession) || !parseU64(fields[3], now))
        return std::nullopt;
    decoded.context.now = static_cast<long long>(now);
    // The command itself may contain tabs.
    decoded.command = join(std::vector<std::string>(fields.begin() + 4, fields.end()), '\t');
    return decoded;
}

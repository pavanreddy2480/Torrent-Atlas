#pragma once

// A state-changing client command as stored in the Raft log, together with
// the random and time inputs the leader chose for it:
//   "<session>\t<salt hex>\t<new session>\t<now>\t<command>"

#include "tracker/state/tracker_state.hpp"

#include <optional>
#include <string>

struct LogCommand {
    u64 session = 0;
    ApplyContext context;
    std::string command;

    std::string encode() const;
    static std::optional<LogCommand> decode(const std::string &entry);
};

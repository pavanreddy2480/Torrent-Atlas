#pragma once

/// @file tracker_service.hpp
/// The tracker's request handler: answers each decrypted client request from
/// TrackerState and logs it.
///
/// Wire format inside the secure channel:
///   request  "C\t<session>\t<command>"
///   reply    "<response>\t<session>"

#include "tracker/state/tracker_state.hpp"

#include <string>

/// Owns the tracker's in-memory state. Thread-safe: handle() may be called
/// from many connection threads at once.
class TrackerService {
public:
    /// Handles one request and logs it (without secrets) to the console.
    /// @param request "C\t<session>\t<command>".
    /// @param client  Who sent it, e.g. "127.0.0.1:50123"; used in the log.
    /// @return "<response>\t<session>", or "ERR malformed request\t0" if the
    ///         request isn't in that form.
    std::string handle(const std::string &request, const std::string &client = "?");

private:
    TrackerState state_;
};

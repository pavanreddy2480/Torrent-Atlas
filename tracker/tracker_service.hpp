#pragma once

/// @file tracker_service.hpp
/// The tracker's request handler: answers each decrypted client request from
/// TrackerState and saves the state to disk after every command that
/// changes it.
///
/// Wire format inside the secure channel:
///   request  "C\t<session>\t<command>"
///   reply    "<response>\t<session>"

#include "tracker/state/tracker_state.hpp"
#include "tracker/state_file.hpp"

#include <mutex>
#include <string>

/// Owns the tracker's state and its file. Thread-safe: handle() may be
/// called from many connection threads at once. Read-only commands run
/// concurrently; state-changing ones run one at a time so each is saved
/// before the next starts.
class TrackerService {
public:
    /// @param file Where the state is loaded from and saved to.
    explicit TrackerService(StateFile file) : file_(std::move(file)) {}

    /// Loads the saved state, if any. Call once before serving.
    /// @return true if the file was loaded or does not exist yet (a fresh
    ///         tracker); false if it exists but is unreadable or corrupt.
    bool load();

    /// Handles one request.
    /// @param request "C\t<session>\t<command>".
    /// @return "<response>\t<session>", or "ERR malformed request\t0" if the
    ///         request isn't in that form. If saving fails, the command still
    ///         takes effect in memory and an error is printed to stderr.
    std::string handle(const std::string &request);

private:
    TrackerState state_;
    StateFile file_;
    std::mutex writeMutex_;   ///< One change-and-save at a time.
};

#pragma once

// The tracker: answers each decrypted client request from TrackerState and
// saves the state to disk after every command that changes it.
//
// Wire format inside the secure channel:
//   request  "C\t<session>\t<command>"
//   reply    "<response>\t<session>"

#include "tracker/state/tracker_state.hpp"
#include "tracker/state_file.hpp"

#include <mutex>
#include <string>

class TrackerService {
public:
    explicit TrackerService(StateFile file) : file_(std::move(file)) {}

    // Loads the saved state. A missing file is a fresh tracker; a corrupt one
    // is an error.
    bool load();
    std::string handle(const std::string &request);

private:
    TrackerState state_;
    StateFile file_;
    std::mutex writeMutex_;   // one change-and-save at a time
};

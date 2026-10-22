#include "tracker/tracker_service.hpp"

#include <filesystem>
#include <iostream>

bool TrackerService::load() {
    std::error_code error;
    if (!std::filesystem::exists(file_.path(), error)) return true;
    std::string saved;
    return file_.read(saved) && state_.restore(saved);
}

std::string TrackerService::handle(const std::string &request) {
    std::vector<std::string> fields = split(request, '\t');
    u64 session = 0;
    if (fields.size() < 3 || fields[0] != "C" || !parseU64(fields[1], session))
        return "ERR malformed request\t0";
    std::string command = join(std::vector<std::string>(fields.begin() + 2, fields.end()), '\t');

    if (!TrackerState::isMutation(command)) {
        CommandResult result = state_.apply(session, command);
        return result.response + "\t" + std::to_string(result.session);
    }
    std::lock_guard<std::mutex> lock(writeMutex_);
    CommandResult result = state_.apply(session, command);
    if (!file_.write(state_.serialize()))
        std::cerr << "tracker: could not save " << file_.path() << '\n';
    return result.response + "\t" + std::to_string(result.session);
}

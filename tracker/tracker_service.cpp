#include "tracker/tracker_service.hpp"

#include "tracker/tracker_log.hpp"

#include <filesystem>

bool TrackerService::load() {
    std::error_code error;
    if (!std::filesystem::exists(file_.path(), error)) {
        TrackerLog::info("No saved state at " + file_.path() + "; starting empty");
        return true;
    }
    std::string saved;
    if (!file_.read(saved) || !state_.restore(saved)) {
        TrackerLog::error("could not read saved state from " + file_.path());
        return false;
    }
    TrackerLog::info("Loaded saved state from " + file_.path());
    return true;
}

std::string TrackerService::handle(const std::string &request, const std::string &client) {
    std::vector<std::string> fields = split(request, '\t');
    u64 session = 0;
    if (fields.size() < 3 || fields[0] != "C" || !parseU64(fields[1], session)) {
        TrackerLog::error(client + " sent a malformed request");
        return "ERR malformed request\t0";
    }
    std::string command = join(std::vector<std::string>(fields.begin() + 2, fields.end()), '\t');
    std::string user = state_.userOf(session);
    std::string who = (user.empty() ? "(not logged in)" : user) + " @ " + client;

    if (!TrackerState::isMutation(command)) {
        CommandResult result = state_.apply(session, command);
        TrackerLog::info(who + ": " + TrackerLog::safeCommand(command) + " -> " +
                         TrackerLog::safeResponse(result.response));
        return result.response + "\t" + std::to_string(result.session);
    }
    std::lock_guard<std::mutex> lock(writeMutex_);
    CommandResult result = state_.apply(session, command);
    TrackerLog::info(who + ": " + TrackerLog::safeCommand(command) + " -> " +
                     TrackerLog::safeResponse(result.response));
    if (!file_.write(state_.serialize()))
        TrackerLog::error("could not save state to " + file_.path());
    return result.response + "\t" + std::to_string(result.session);
}

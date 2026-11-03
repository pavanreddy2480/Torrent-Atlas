#include "tracker/tracker_log.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

std::mutex TrackerLog::mutex_;

void TrackerLog::info(const std::string &message) { write(message); }

void TrackerLog::error(const std::string &message) { write("ERROR: " + message); }

void TrackerLog::write(const std::string &line) {
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm local{};
    localtime_r(&now, &local);
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << '[' << std::put_time(&local, "%H:%M:%S") << "] " << line << std::endl;
}

std::string TrackerLog::safeCommand(const std::string &commandLine) {
    // How many arguments of each command may be shown; the rest are hidden.
    static const std::map<std::string, std::size_t> shown = {
        {"create_user", 1}, {"login", 1}, {"upload_file", 2}};
    std::istringstream input(commandLine);
    std::vector<std::string> words;
    for (std::string word; input >> word;) words.push_back(word);
    if (words.empty()) return "(empty)";

    auto limit = shown.find(words[0]);
    std::string text = words[0];
    for (std::size_t i = 1; i < words.size(); ++i) {
        bool hidden = limit != shown.end() && i > limit->second;
        if (hidden && i > limit->second + 1) continue;   // one "***" for all hidden words
        text += hidden ? " ***" : " " + words[i];
    }
    return text;
}

std::string TrackerLog::safeResponse(const std::string &response) {
    if (response.rfind("META", 0) == 0) return "META ...";
    const std::size_t limit = 200;
    return response.size() <= limit ? response : response.substr(0, limit) + "...";
}

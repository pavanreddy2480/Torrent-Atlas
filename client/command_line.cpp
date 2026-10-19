#include "client/command_line.hpp"

#include <cctype>
#include <set>

std::vector<std::string> parseCommandWords(const std::string &line) {
    std::vector<std::string> words;
    std::string current;
    char quote = '\0';
    bool escaped = false;
    bool inWord = false;
    for (char c : line) {
        if (escaped) {
            current.push_back(c);
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (quote) {
            if (c == quote) quote = '\0';
            else current.push_back(c);
        } else if (c == '\'' || c == '"') {
            quote = c;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            if (inWord) words.push_back(current);
            current.clear();
            inWord = false;
            continue;
        } else {
            current.push_back(c);
        }
        inWord = true;
    }
    if (escaped) current.push_back('\\');
    if (inWord) words.push_back(current);
    return words;
}

CommandLine CommandLine::parse(const std::string &line) {
    static const std::set<std::string> verbs = {"create", "join", "leave",  "list",   "accept",
                                                "upload", "download", "stop", "show", "cancel",
                                                "resume"};
    std::vector<std::string> words = parseCommandWords(line);
    if (words.empty()) return {};
    std::size_t argsStart = 1;
    std::string name = words[0];
    if (words.size() >= 2 && name.find('_') == std::string::npos && verbs.count(name)) {
        name += "_" + words[1];
        argsStart = 2;
    }
    return {name, std::vector<std::string>(words.begin() + argsStart, words.end())};
}

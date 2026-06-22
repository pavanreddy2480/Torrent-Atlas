#pragma once

#include <cctype>
#include <string>
#include <vector>

inline std::vector<std::string> parseCommandWords(const std::string &line) {
    std::vector<std::string> result;
    std::string current;
    char quote = '\0';
    bool escaped = false;
    bool tokenStarted = false;
    for (char character : line) {
        if (escaped) {
            current.push_back(character);
            escaped = false;
            tokenStarted = true;
        } else if (character == '\\') {
            escaped = true;
            tokenStarted = true;
        } else if (quote) {
            if (character == quote) quote = '\0';
            else current.push_back(character);
            tokenStarted = true;
        } else if (character == '\'' || character == '"') {
            quote = character;
            tokenStarted = true;
        } else if (std::isspace(static_cast<unsigned char>(character))) {
            if (tokenStarted) {
                result.push_back(current);
                current.clear();
                tokenStarted = false;
            }
        } else {
            current.push_back(character);
            tokenStarted = true;
        }
    }
    if (escaped) current.push_back('\\');
    if (tokenStarted) result.push_back(current);
    return result;
}

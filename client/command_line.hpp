#pragma once

// A command typed at the client prompt. Two-word spellings are accepted:
// "create user alice pw" and "create_user alice pw" both give
// name "create_user" and args {"alice", "pw"}.

#include <string>
#include <vector>

// Splits a line into words. Quotes and backslashes work like a shell's, so
// "my file.pdf" and my\ file.pdf are one word.
std::vector<std::string> parseCommandWords(const std::string &line);

struct CommandLine {
    std::string name;
    std::vector<std::string> args;

    static CommandLine parse(const std::string &line);
};

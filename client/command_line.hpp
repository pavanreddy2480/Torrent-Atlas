#pragma once

/// @file command_line.hpp
/// Parsing what the user types at the client prompt.

#include <string>
#include <vector>

/// Splits a line into words the way a shell would: single or double quotes
/// group words ("my file.pdf"), and a backslash escapes the next character
/// (my\ file.pdf). Quotes and escaping backslashes are removed.
/// @return The words; empty for a blank line. An unterminated quote runs to
///         the end of the line.
std::vector<std::string> parseCommandWords(const std::string &line);

/// One typed command, normalized.
struct CommandLine {
    std::string name;                ///< e.g. "create_user"; empty for a blank line.
    std::vector<std::string> args;   ///< The remaining words.

    /// Parses a line. Two-word spellings are joined with '_' when the first
    /// word is a known verb (create, join, leave, list, accept, remove,
    /// upload, download, stop, show, cancel, resume): "create user alice pw"
    /// and "create_user alice pw" both give name "create_user" and args
    /// {"alice", "pw"}.
    static CommandLine parse(const std::string &line);
};

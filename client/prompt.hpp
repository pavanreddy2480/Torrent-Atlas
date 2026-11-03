#pragma once

/// @file prompt.hpp
/// The client's "> " command prompt, with line editing and up-arrow history
/// when typed at a terminal.

#include <istream>
#include <ostream>
#include <string>

/// Reads one command line at a time.
///
/// When in is std::cin and stdin is a terminal, lines come from libedit's
/// readline(), so arrow keys edit the line and recall earlier commands.
/// Otherwise (piped input, tests) it prints "> " to out and uses getline.
class Prompt {
public:
    Prompt(std::istream &in, std::ostream &out);

    /// Shows the prompt and reads the next line into line.
    /// @return false at end of input.
    bool read(std::string &line);

private:
    /// Reads with libedit and adds non-blank lines to the history.
    bool readEdited(std::string &line);

    std::istream &in_;
    std::ostream &out_;
    const bool interactive_;
};

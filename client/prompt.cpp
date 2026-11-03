#include "client/prompt.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <unistd.h>

// macOS ships libedit's readline API as <readline/readline.h>; Linux's
// libedit-dev puts it at <editline/readline.h>.
#if __has_include(<editline/readline.h>)
#include <editline/readline.h>
#else
#include <readline/history.h>
#include <readline/readline.h>
#endif

Prompt::Prompt(std::istream &in, std::ostream &out)
    : in_(in), out_(out), interactive_(&in == &std::cin && isatty(STDIN_FILENO)) {}

bool Prompt::read(std::string &line) {
    if (interactive_) return readEdited(line);
    out_ << "> ";
    return static_cast<bool>(std::getline(in_, line));
}

bool Prompt::readEdited(std::string &line) {
    out_.flush();
    std::unique_ptr<char, decltype(&std::free)> text(readline("> "), &std::free);
    if (!text) return false;
    line = text.get();
    if (line.find_first_not_of(" \t") != std::string::npos) add_history(text.get());
    return true;
}

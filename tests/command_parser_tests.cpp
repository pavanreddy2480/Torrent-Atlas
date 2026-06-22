#include "../common/command_parser.hpp"

#include <cassert>
#include <iostream>
#include <vector>

int main() {
    assert(parseCommandWords("login alice secret") ==
           (std::vector<std::string>{"login", "alice", "secret"}));
    assert(parseCommandWords("upload file demo \"folder/my file.pdf\"") ==
           (std::vector<std::string>{"upload", "file", "demo",
                                     "folder/my file.pdf"}));
    assert(parseCommandWords("download_file demo 'my file.pdf' /tmp/output\\ file.pdf") ==
           (std::vector<std::string>{"download_file", "demo", "my file.pdf",
                                     "/tmp/output file.pdf"}));
    assert(parseCommandWords("create group \"\"") ==
           (std::vector<std::string>{"create", "group", ""}));

    std::cout << "command parser tests passed\n";
}

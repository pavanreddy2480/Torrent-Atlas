#include "../client/command_line.hpp"

#include <cassert>
#include <iostream>

using Words = std::vector<std::string>;

int main() {
    assert(parseCommandWords("login alice secret") == (Words{"login", "alice", "secret"}));
    assert(parseCommandWords("upload file demo \"folder/my file.pdf\"") ==
           (Words{"upload", "file", "demo", "folder/my file.pdf"}));
    assert(parseCommandWords("download_file demo 'my file.pdf' /tmp/output\\ file.pdf") ==
           (Words{"download_file", "demo", "my file.pdf", "/tmp/output file.pdf"}));
    assert(parseCommandWords("create group \"\"") == (Words{"create", "group", ""}));

    CommandLine twoWords = CommandLine::parse("create user alice pw");
    assert(twoWords.name == "create_user" && twoWords.args == (Words{"alice", "pw"}));
    CommandLine underscored = CommandLine::parse("create_user alice pw");
    assert(underscored.name == "create_user" && underscored.args == (Words{"alice", "pw"}));
    CommandLine single = CommandLine::parse("logout");
    assert(single.name == "logout" && single.args.empty());
    CommandLine other = CommandLine::parse("login alice pw");
    assert(other.name == "login" && other.args == (Words{"alice", "pw"}));
    assert(CommandLine::parse("   ").name.empty());

    std::cout << "command line tests passed\n";
}

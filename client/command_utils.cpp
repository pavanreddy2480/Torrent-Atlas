#include "command_utils.hpp"

#include "../common/command_parser.hpp"

std::vector<std::string> commandWords(const std::string &line) {
    return parseCommandWords(line);
}

std::string canonicalCommand(const std::vector<std::string> &arguments) {
    if (arguments.empty()) return "";
    if (arguments[0].find('_') != std::string::npos ||
        arguments.size() == 1)
        return arguments[0];
    if ((arguments[0] == "create" || arguments[0] == "join" ||
         arguments[0] == "leave" || arguments[0] == "list" ||
         arguments[0] == "accept" || arguments[0] == "upload" ||
         arguments[0] == "download" || arguments[0] == "stop" ||
         arguments[0] == "show" || arguments[0] == "cancel") &&
        arguments.size() >= 2)
        return arguments[0] + "_" + arguments[1];
    if (arguments[0] == "resume" && arguments.size() >= 2)
        return arguments[0] + "_" + arguments[1];
    return arguments[0];
}

std::string safeCommandForLog(const std::string &line) {
    std::vector<std::string> arguments = commandWords(line);
    if (arguments.empty()) return "";
    std::string command = canonicalCommand(arguments);
    if ((command == "login" || command == "create_user") &&
        arguments.size() >= 2) {
        std::size_t userIndex = command == arguments[0] ? 1 : 2;
        if (userIndex < arguments.size())
            return command + " " + arguments[userIndex] + " ********";
    }
    return line;
}

bool commandContainsPassword(const std::string &line) {
    std::vector<std::string> arguments = commandWords(line);
    if (arguments.empty()) return false;
    std::string command = canonicalCommand(arguments);
    return command == "login" || command == "create_user";
}

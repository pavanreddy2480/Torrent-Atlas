#pragma once

#include <string>
#include <vector>

std::vector<std::string> commandWords(const std::string &line);
std::string canonicalCommand(const std::vector<std::string> &arguments);
std::string safeCommandForLog(const std::string &line);
bool commandContainsPassword(const std::string &line);

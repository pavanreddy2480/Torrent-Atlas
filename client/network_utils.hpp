#pragma once

#include "client_types.hpp"

#include <string>
#include <vector>

std::string endpointKey(const Endpoint &endpoint);
bool parseEndpoint(const std::string &text, Endpoint &endpoint);
bool loadTrackerInfo(const std::string &path,
                     std::vector<Endpoint> &trackers);

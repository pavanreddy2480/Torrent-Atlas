#pragma once

#include "client_types.hpp"

#include <string>

#include <vector>

// client.conf: one tracker IP:PORT per line, then the cluster's hex Ed25519
// public key (written by torrent_keygen).
bool loadTrackerInfo(const std::string &path, std::vector<Endpoint> &trackers,
                     std::string &serverPublicKey);

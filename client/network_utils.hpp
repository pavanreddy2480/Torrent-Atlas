#pragma once

#include "client_types.hpp"

#include <string>

// client.conf: the load balancer's IP:PORT, then its hex Ed25519 public key.
bool loadTrackerInfo(const std::string &path, Endpoint &tracker,
                     std::string &serverPublicKey);

/// @file tracker/main.cpp
/// tracker <IP:PORT> <keys-dir>
///
/// Runs the tracker: loads its identity key from keys-dir, then serves
/// clients on IP:PORT, one thread per connection, one encrypted request per
/// connection. All state is in memory; a restart starts empty.
/// Type "quit" on stdin to stop it; with stdin closed it runs until killed.
/// Exit code 0 after quit, 1 on a startup error.

#include "tracker/tracker_log.hpp"
#include "tracker/tracker_service.hpp"

#include "common/config/tracker_identity.hpp"
#include "common/net/secure_channel.hpp"
#include "common/net/tcp_server.hpp"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
    std::optional<Endpoint> address = argc == 3 ? Endpoint::parse(argv[1]) : std::nullopt;
    if (!address) {
        std::cerr << "usage: " << argv[0] << " <ip:port> <keys-dir>\n";
        return 1;
    }
    std::optional<TrackerIdentity> identity = TrackerIdentity::load(argv[2]);
    if (!identity) {
        std::cerr << "missing tracker identity key in " << argv[2] << " (run torrent_keygen)\n";
        return 1;
    }
    TrackerLog::info("Loaded tracker identity key from " + std::string(argv[2]));
    TrackerService tracker;
    TcpServer server([&](Socket socket) {
        std::optional<Endpoint> peer = socket.peer();
        std::string client = peer ? peer->toString() : "unknown client";
        TrackerLog::info("Connection from " + client);
        socket.setTimeout(5);
        std::optional<SecureChannel> channel =
            SecureChannel::accept(std::move(socket), identity->privateKey());
        std::string request;
        if (!channel) return TrackerLog::error(client + ": secure handshake failed");
        if (!channel->receive(request)) return TrackerLog::error(client + ": no request received");
        if (!channel->send(tracker.handle(request, client)))
            TrackerLog::error(client + ": could not send the reply");
    });
    if (!server.listen(*address)) {
        TrackerLog::error("could not listen on " + address->toString() + ": " +
                          std::strerror(errno));
        return 1;
    }
    TrackerLog::info("Tracker serving clients on " + address->toString() +
                     " (type \"quit\" to stop)");

    // Without a console (stdin at end of file) the tracker runs until killed.
    std::thread console([&] {
        for (std::string line; std::getline(std::cin, line);) {
            if (line == "quit") {
                TrackerLog::info("Stopping: waiting for open connections to finish");
                return server.stop();
            }
            if (!line.empty()) TrackerLog::info("Unknown console command \"" + line + "\"; type quit");
        }
    });
    server.serve();
    console.join();
    TrackerLog::info("Tracker stopped");
    return 0;
}

// tracker <IP:PORT> <keys-dir> <data-dir>
// Runs the tracker. Type "quit" on stdin to stop it.

#include "tracker/tracker_service.hpp"

#include "common/config/tracker_identity.hpp"
#include "common/net/secure_channel.hpp"
#include "common/net/tcp_server.hpp"

#include <filesystem>
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
    std::optional<Endpoint> address = argc == 4 ? Endpoint::parse(argv[1]) : std::nullopt;
    if (!address) {
        std::cerr << "usage: " << argv[0] << " <ip:port> <keys-dir> <data-dir>\n";
        return 1;
    }
    std::optional<TrackerIdentity> identity = TrackerIdentity::load(argv[2]);
    if (!identity) {
        std::cerr << "missing tracker identity key in " << argv[2] << " (run torrent_keygen)\n";
        return 1;
    }
    std::string dataDir = argv[3];
    std::error_code ignored;
    std::filesystem::create_directories(dataDir, ignored);
    std::filesystem::permissions(dataDir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ignored);

    TrackerService tracker(StateFile(dataDir + "/tracker.state"));
    if (!tracker.load()) {
        std::cerr << "could not read " << dataDir << "/tracker.state\n";
        return 1;
    }
    TcpServer server([&](Socket socket) {
        socket.setTimeout(5);
        std::optional<SecureChannel> channel =
            SecureChannel::accept(std::move(socket), identity->privateKey());
        std::string request;
        if (channel && channel->receive(request)) channel->send(tracker.handle(request));
    });
    if (!server.listen(*address)) {
        perror("tracker listen");
        return 1;
    }
    std::cerr << "Tracker serving clients on " << address->toString() << '\n';

    // Without a console (stdin at end of file) the tracker runs until killed.
    std::thread console([&] {
        for (std::string line; std::getline(std::cin, line);)
            if (line == "quit") return server.stop();
    });
    server.serve();
    console.join();
    return 0;
}

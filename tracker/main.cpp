// tracker <cluster.conf> <node-id> <keys-dir> <data-dir>
// Runs one tracker node. Type "quit" on stdin to stop it.

#include "raft_node.hpp"

#include "../common/secure_channel.hpp"
#include "../common/tcp_server.hpp"

#include <filesystem>
#include <iostream>
#include <thread>

int main(int argc, char **argv) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " <cluster.conf> <node-id> <keys-dir> <data-dir>\n";
        return 1;
    }
    std::optional<ClusterConfig> cluster = ClusterConfig::load(argv[1]);
    if (!cluster) {
        std::cerr << "cluster.conf needs an odd number (3 or more) of lines: "
                     "<id> <client IP:PORT> <raft IP:PORT>\n";
        return 1;
    }
    u64 id = 0;
    const ClusterMember *self =
        parseU64(argv[2], id) && id <= 1000 ? cluster->find(static_cast<int>(id)) : nullptr;
    if (!self) {
        std::cerr << "node id not found in cluster.conf\n";
        return 1;
    }
    std::optional<NodeKeys> keys = NodeKeys::load(argv[3], self->id);
    if (!keys) {
        std::cerr << "missing keys in " << argv[3] << " (run torrent_keygen)\n";
        return 1;
    }
    std::string dataDir = argv[4];
    std::error_code ignored;
    std::filesystem::create_directories(dataDir, ignored);
    std::filesystem::permissions(dataDir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ignored);

    RaftNode node(*self, *cluster, *keys);
    TcpServer server([&](Socket socket) {
        socket.setTimeout(5);
        std::optional<SecureChannel> channel =
            SecureChannel::accept(std::move(socket), keys->identityKey);
        std::string request;
        if (channel && channel->receive(request)) channel->send(node.handle(request));
    });
    if (!server.listen(self->client)) {
        perror("tracker listen");
        return 1;
    }
    if (!node.start(dataDir)) {
        std::cerr << "raft server failed to start\n";
        return 1;
    }
    std::cerr << "Tracker " << self->id << " serving clients on " << self->client.toString()
              << ", raft on " << self->raft.toString() << '\n';

    // Without a console (stdin at end of file) the tracker runs until killed.
    std::thread console([&] {
        for (std::string line; std::getline(std::cin, line);)
            if (line == "quit") return server.stop();
    });
    server.serve();
    console.join();
    node.stop();
    return 0;
}

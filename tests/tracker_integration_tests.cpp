// Three NuRaft trackers: leader election, majority commit, failover,
// catch-up, durability, and the security of both channels.
#include "cluster_test_support.hpp"

#include <cstdlib>
#include <iostream>

using namespace cluster_test;

static void require(bool condition, const std::string &message) {
    if (!condition) throw std::runtime_error(message);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    std::string dir = "/tmp/torrent-raft-integration-" + std::to_string(getpid());
    Cluster cluster;
    try {
        if (!cluster.setup(argv[1], dir)) {
            std::cout << "tracker integration tests skipped: local sockets unavailable\n";
            return 77;
        }
        cluster.startAll();

        // Writes go through the elected leader and commit on a majority.
        require(cluster.request(0, "create_user alice secret").text == "OK user created",
                "create_user failed");
        Response login = cluster.request(0, "login alice secret");
        require(login.text == "OK logged in" && login.session != 0, "login failed");
        u64 session = login.session;
        require(cluster.request(session, "create_group demo").text == "OK group created",
                "create_group failed");
        require(cluster.request(session, "list_groups").text == "OK demo",
                "read after write failed");

        // Followers point clients at the leader.
        int leader = cluster.leader();
        require(leader >= 0, "no leader elected");
        std::size_t follower = (static_cast<std::size_t>(leader) + 1) % 3;
        Response redirected;
        require(cluster.requestTo(follower, session, "list_groups", redirected) &&
                    redirected.text ==
                        "REDIRECT " + endpointKey(cluster.members[leader].client),
                "follower did not redirect to the leader: " + redirected.text);

        // Leader crash: the other two elect a new leader and keep every write.
        cluster.stop(static_cast<std::size_t>(leader));
        require(cluster.request(session, "list_groups").text == "OK demo",
                "acknowledged write lost after leader crash");
        require(cluster.request(session, "create_group afterfail").text == "OK group created",
                "new leader did not accept writes");
        int newLeader = cluster.leader();
        require(newLeader >= 0 && newLeader != leader, "no new leader after crash");

        // Two of three down: no majority, so writes are refused, never half-applied.
        cluster.stop(static_cast<std::size_t>(newLeader));
        Response noQuorum = cluster.request(session, "create_group lonely", 6);
        require(noQuorum.text.rfind("OK", 0) != 0, "write succeeded without a majority");

        // Restart the crashed nodes: they rejoin, catch up from the log, and the
        // cluster accepts writes again.
        cluster.start(static_cast<std::size_t>(leader));
        cluster.start(static_cast<std::size_t>(newLeader));
        Response groups = cluster.request(session, "list_groups");
        require(groups.text == "OK afterfail demo", "unexpected state after restart: " + groups.text);
        require(cluster.request(session, "create_group rejoined").text == "OK group created",
                "write failed after nodes rejoined");

        // Durability: crash all three, restart, state and sessions are intact.
        cluster.stopAll();
        cluster.startAll();
        require(cluster.request(session, "list_groups").text == "OK afterfail demo rejoined",
                "state lost after full restart");
        require(cluster.request(0, "login alice wrong").text == "ERR invalid password",
                "password check failed after restart");

        // Client channel: a wrong pinned key or a plain-text request gets nothing.
        std::string wrongPrivate, wrongPublic;
        require(ed25519KeyPair(wrongPrivate, wrongPublic), "keygen failed");
        Response rejected;
        require(!cluster.requestTo(0, 0, "list_groups", rejected, wrongPublic),
                "client accepted a tracker it could not authenticate");
        {
            UniqueFd fd(connectTcp("127.0.0.1", cluster.clientPort(0), 2));
            std::string response;
            require(fd && sendFrame(fd.get(), "C\t0\tlogin alice secret") &&
                        !receiveFrame(fd.get(), response),
                    "tracker answered a plain-text request");
        }
        // A recorded request replayed on a new connection fails to decrypt.
        {
            int target = cluster.leader();
            UniqueFd fd(connectTcp("127.0.0.1", cluster.clientPort(target), 2));
            std::string sessionKey, response;
            require(fd && clientHandshake(fd.get(), cluster.publicKey, sessionKey),
                    "handshake failed");
            AesGcmMessage message;
            require(aes256GcmEncrypt(sessionKey, "client->tracker",
                                     "C\t0\tcreate_user mallory secret", message),
                    "encrypt failed");
            std::string sealed = message.nonce + message.tag + message.ciphertext;
            require(sendFrame(fd.get(), sealed) &&
                        sealedReceive(fd.get(), sessionKey, "tracker->client", response),
                    "sealed request failed");
            UniqueFd replay(connectTcp("127.0.0.1", cluster.clientPort(target), 2));
            std::string newKey;
            require(replay && clientHandshake(replay.get(), cluster.publicKey, newKey) &&
                        sendFrame(replay.get(), sealed) && !receiveFrame(replay.get(), response),
                    "tracker accepted a replayed request");
        }
        // Raft port: a peer without a cluster certificate can't complete TLS.
        {
            UniqueFd fd(connectTcp("127.0.0.1", cluster.members[0].raft.port, 2));
            std::string response;
            require(fd && sendFrame(fd.get(), "not a tls handshake") &&
                        !receiveFrame(fd.get(), response),
                    "raft port answered a non-TLS peer");
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        cluster.stopAll();
        std::system(("rm -rf " + dir).c_str());
        return 1;
    }
    cluster.stopAll();
    std::system(("rm -rf " + dir).c_str());
    std::cout << "tracker integration tests passed\n";
    return 0;
}

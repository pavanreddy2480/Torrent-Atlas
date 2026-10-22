/// @file tracker_integration_tests.cpp
/// The tracker process: commands, durability across a crash, no plaintext
/// passwords on disk, and the security of the client channel.
/// Usage: tracker_integration_tests <tracker binary>
#include "tracker_test_support.hpp"

#include "common/crypto/crypto.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

using namespace tracker_test;

/// Fails the test with message unless condition holds.
/// @throws std::runtime_error
static void require(bool condition, const std::string &message) {
    if (!condition) throw std::runtime_error(message);
}

/// @return true if any file under dir contains text, as is or hex-encoded.
static bool anyFileContains(const std::string &dir, const std::string &text) {
    for (const auto &entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream input(entry.path(), std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
        if (contents.find(text) != std::string::npos ||
            contents.find(toHex(text)) != std::string::npos)
            return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    std::string dir = "/tmp/torrent-tracker-integration-" + std::to_string(getpid());
    TrackerProcess tracker;
    try {
        if (!tracker.setup(argv[1], dir)) {
            std::cout << "tracker integration tests skipped: local sockets unavailable\n";
            return 77;
        }
        tracker.start();

        require(tracker.request(0, "create_user alice Hunter2pass").text == "OK user created",
                "create_user failed");
        require(tracker.request(0, "login alice WrongGuess99").text == "ERR invalid password",
                "wrong password accepted");
        Response login = tracker.request(0, "login alice Hunter2pass");
        require(login.text == "OK logged in" && login.session != 0, "login failed");
        u64 session = login.session;
        require(tracker.request(session, "create_group demo").text == "OK group created",
                "create_group failed");
        require(tracker.request(session, "list_groups").text == "OK demo",
                "read after write failed");

        // Only password hashes reach the disk, never the passwords typed.
        require(!anyFileContains(tracker.dataDir, "Hunter2pass") &&
                    !anyFileContains(tracker.dataDir, "WrongGuess99"),
                "a plaintext password was written to the tracker's data directory");

        // Crash and restart: every acknowledged change and the session survive.
        tracker.stop();
        tracker.start();
        require(tracker.request(session, "list_groups").text == "OK demo",
                "state lost after restart");
        require(tracker.request(session, "create_group after").text == "OK group created",
                "write failed after restart");
        require(tracker.request(0, "login alice wrong").text == "ERR invalid password",
                "password check failed after restart");

        // Client channel: a wrong pinned key or a plain-text request gets nothing.
        std::optional<crypto::KeyPair> wrongKey = crypto::ed25519KeyPair();
        require(wrongKey.has_value(), "keygen failed");
        Response rejected;
        require(!tracker.request(0, "list_groups", rejected, wrongKey->publicKey),
                "client accepted a tracker it could not authenticate");
        {
            Socket socket = Socket::connect(tracker.address, 2);
            std::string response;
            require(socket && socket.sendFrame("C\t0\tlogin alice secret") &&
                        !socket.receiveFrame(response),
                    "tracker answered a plain-text request");
        }
        // A recorded request replayed on a new connection fails to decrypt.
        {
            auto channel = SecureChannel::connect(Socket::connect(tracker.address, 2),
                                                  tracker.publicKey);
            require(channel.has_value(), "handshake failed");
            std::string sealed = channel->seal("C\t0\tcreate_user mallory secret");
            std::string response;
            require(channel->socket().sendFrame(sealed) && channel->receive(response),
                    "sealed request failed");
            auto replay = SecureChannel::connect(Socket::connect(tracker.address, 2),
                                                 tracker.publicKey);
            require(replay && replay->socket().sendFrame(sealed) &&
                        !replay->socket().receiveFrame(response),
                    "tracker accepted a replayed request");
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        tracker.stop();
        std::system(("rm -rf " + dir).c_str());
        return 1;
    }
    tracker.stop();
    std::system(("rm -rf " + dir).c_str());
    std::cout << "tracker integration tests passed\n";
    return 0;
}

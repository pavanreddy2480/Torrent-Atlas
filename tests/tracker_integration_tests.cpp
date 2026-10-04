#include "../common/secure_channel.hpp"

#include <cassert>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/wait.h>
#include <thread>

struct TrackerProcess {
    pid_t pid = -1;
};

static int unusedPort() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof(address);
    assert(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    int port = ntohs(address.sin_port);
    close(fd);
    return port;
}

static std::string clusterKey;
static std::string clusterKeyPath;

static TrackerProcess startTracker(const std::string &binary,
                                   const std::string &infoPath,
                                   int number) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int nullFd = open("/dev/null", O_RDONLY);
        if (nullFd >= 0) {
            dup2(nullFd, STDIN_FILENO);
            close(nullFd);
        }
        std::string numberText = std::to_string(number);
        execl(binary.c_str(), binary.c_str(), infoPath.c_str(), clusterKeyPath.c_str(),
              numberText.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }
    return {pid};
}

static void stopTracker(TrackerProcess &process) {
    if (process.pid <= 0) return;
    kill(process.pid, SIGTERM);
    int status = 0;
    waitpid(process.pid, &status, 0);
    process.pid = -1;
}

static bool waitForTracker(int port) {
    for (int attempt = 0; attempt < 100; ++attempt) {
        int fd = connectTcp("127.0.0.1", port, 1);
        if (fd >= 0) {
            close(fd);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

static std::pair<std::string, u64> request(int port, u64 session,
                                           const std::string &command) {
    std::string response;
    assert(clusterCall({"127.0.0.1", port}, clusterKey,
                       "C\t" + std::to_string(session) + "\t" + command, response));
    std::size_t tab = response.rfind('\t');
    assert(tab != std::string::npos);
    u64 returnedSession = static_cast<u64>(std::stoull(response.substr(tab + 1)));
    response.resize(tab);
    return {response, returnedSession};
}

static std::pair<std::string, u64> eventuallyRequest(
    int port, u64 session, const std::string &command,
    const std::string &expectedPrefix) {
    std::pair<std::string, u64> result;
    for (int attempt = 0; attempt < 100; ++attempt) {
        result = request(port, session, command);
        if (result.first.rfind(expectedPrefix, 0) == 0) return result;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return result;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    int ports[3];
    for (int index = 0; index < 3; ++index) {
        ports[index] = unusedPort();
        if (ports[index] < 0) {
            std::cout << "tracker integration tests skipped: local sockets unavailable\n";
            return 77;
        }
        for (int earlier = 0; earlier < index; ++earlier)
            while (ports[index] == ports[earlier]) ports[index] = unusedPort();
    }
    const int writePort = ports[0], readPortA = ports[1], readPortB = ports[2];
    std::string infoPath = "/tmp/torrent-tracker-integration-" +
                           std::to_string(getpid()) + ".txt";
    {
        std::ofstream output(infoPath);
        for (int port : ports) output << "127.0.0.1:" << port << '\n';
    }
    clusterKey = randomBytes(32);
    clusterKeyPath = infoPath + ".key";
    assert(writeKeyFile(clusterKeyPath, clusterKey, true));

    TrackerProcess nodes[3];
    for (int index = 0; index < 3; ++index)
        nodes[index] = startTracker(argv[1], infoPath, index + 1);
    for (int port : ports) assert(waitForTracker(port));

    // Writes go to the write server once it has found a read server.
    auto created = eventuallyRequest(writePort, 0, "create_user alice secret", "OK");
    assert(created.first == "OK user created");
    auto aliceLogin = request(writePort, 0, "login alice secret");
    assert(aliceLogin.first == "OK logged in");
    assert(request(writePort, aliceLogin.second, "create_group demo").first ==
           "OK group created");

    // Replication is synchronous once the read servers are in sync, so the
    // next read on either read server sees the write.
    auto groupsA = eventuallyRequest(readPortA, aliceLogin.second, "list_groups", "OK demo");
    auto groupsB = eventuallyRequest(readPortB, aliceLogin.second, "list_groups", "OK demo");
    assert(groupsA.first == "OK demo");
    assert(groupsB.first == "OK demo");
    assert(request(writePort, aliceLogin.second, "create_group second").first ==
           "OK group created");
    assert(request(readPortA, aliceLogin.second, "list_groups").first == "OK demo second");
    assert(request(readPortB, aliceLogin.second, "list_groups").first == "OK demo second");

    // Read servers refuse writes.
    assert(request(readPortA, 0, "create_user bob secret").first.rfind(
               "ERR read-only server", 0) == 0);

    // Frames without the cluster key are refused, and data is untouched.
    {
        UniqueFd fd(connectTcp("127.0.0.1", readPortA, 2));
        std::string response;
        assert(fd && sendFrame(fd.get(), "P\t99\n") && receiveFrame(fd.get(), response));
        assert(response == "ERR unauthenticated cluster frame");
        std::string forged;
        assert(!clusterCall({"127.0.0.1", readPortA}, randomBytes(32), "P\t99\n", forged));
        assert(request(readPortA, aliceLogin.second, "list_groups").first == "OK demo second");
    }

    // A restarted read server is caught up by a snapshot push.
    stopTracker(nodes[2]);
    assert(request(writePort, aliceLogin.second, "create_group third").first ==
           "OK group created");
    nodes[2] = startTracker(argv[1], infoPath, 3);
    assert(waitForTracker(readPortB));
    assert(eventuallyRequest(readPortB, aliceLogin.second, "list_groups",
                             "OK demo second third").first == "OK demo second third");

    // A restarted write server recovers its state from the read servers.
    stopTracker(nodes[0]);
    nodes[0] = startTracker(argv[1], infoPath, 1);
    assert(waitForTracker(writePort));
    assert(eventuallyRequest(writePort, aliceLogin.second, "list_groups",
                             "OK demo second third").first == "OK demo second third");
    assert(request(writePort, aliceLogin.second, "create_group fourth").first ==
           "OK group created");
    assert(request(readPortA, aliceLogin.second, "list_groups").first ==
           "OK demo fourth second third");

    // State is in memory only: restarting every node starts empty.
    for (auto &node : nodes) stopTracker(node);
    for (int index = 0; index < 3; ++index)
        nodes[index] = startTracker(argv[1], infoPath, index + 1);
    for (int port : ports) assert(waitForTracker(port));
    assert(eventuallyRequest(writePort, 0, "login alice secret", "ERR no such user").first ==
           "ERR no such user");

    for (auto &node : nodes) stopTracker(node);
    unlink(infoPath.c_str());
    unlink(clusterKeyPath.c_str());
    std::cout << "tracker integration tests passed\n";
}

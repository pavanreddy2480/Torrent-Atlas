#include "../common/protocol.hpp"

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
        execl(binary.c_str(), binary.c_str(), infoPath.c_str(),
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
    int fd = connectTcp("127.0.0.1", port, 2);
    assert(fd >= 0);
    std::string response;
    assert(sendFrame(fd, "C\t" + std::to_string(session) + "\t" + command));
    assert(receiveFrame(fd, response));
    close(fd);
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
    int firstPort = unusedPort();
    int secondPort = unusedPort();
    if (firstPort < 0 || secondPort < 0) {
        std::cout << "tracker integration tests skipped: local sockets unavailable\n";
        return 77;
    }
    while (secondPort == firstPort) secondPort = unusedPort();
    std::string infoPath = "/tmp/torrent-tracker-integration-" +
                           std::to_string(getpid()) + ".txt";
    {
        std::ofstream output(infoPath);
        output << "127.0.0.1:" << firstPort << '\n'
               << "127.0.0.1:" << secondPort << '\n';
    }

    TrackerProcess first = startTracker(argv[1], infoPath, 1);
    TrackerProcess second = startTracker(argv[1], infoPath, 2);
    assert(waitForTracker(firstPort));
    assert(waitForTracker(secondPort));

    assert(request(firstPort, 0, "create_user alice secret").first ==
           "OK user created");
    auto aliceLogin = request(firstPort, 0, "login alice secret");
    assert(aliceLogin.first == "OK logged in");
    assert(request(firstPort, aliceLogin.second, "create_group demo").first ==
           "OK group created");

    assert(request(secondPort, 0, "create_user bob secret").first ==
           "OK user created");
    auto bobLogin = request(secondPort, 0, "login bob secret");
    assert(bobLogin.first == "OK logged in");
    auto joined = eventuallyRequest(
        secondPort, bobLogin.second, "join_group demo", "OK");
    assert(joined.first == "OK join requested");

    auto accepted = eventuallyRequest(
        firstPort, aliceLogin.second, "accept_request demo bob", "OK");
    assert(accepted.first == "OK request accepted");
    auto groups = eventuallyRequest(
        secondPort, bobLogin.second, "list_groups", "OK");
    assert(groups.first.find("demo") != std::string::npos);

    stopTracker(first);
    stopTracker(second);

    first = startTracker(argv[1], infoPath, 1);
    second = startTracker(argv[1], infoPath, 2);
    assert(waitForTracker(firstPort));
    assert(waitForTracker(secondPort));
    assert(request(firstPort, 0, "login alice secret").first ==
           "ERR no such user");

    stopTracker(first);
    stopTracker(second);
    unlink(infoPath.c_str());
    std::cout << "tracker integration tests passed\n";
}

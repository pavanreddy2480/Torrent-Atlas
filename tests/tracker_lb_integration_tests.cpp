#include "../common/protocol.hpp"

#include <cassert>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <vector>

struct ChildProcess {
    pid_t pid = -1;
};

static void require(bool condition, const std::string &message) {
    if (!condition) throw std::runtime_error(message);
}

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
    require(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) == 0,
            "getsockname failed");
    int port = ntohs(address.sin_port);
    close(fd);
    return port;
}

static ChildProcess startProcess(const std::vector<std::string> &arguments,
                                 const std::string &logPath = "") {
    pid_t pid = fork();
    require(pid >= 0, "fork failed");
    if (pid == 0) {
        int nullIn = open("/dev/null", O_RDONLY);
        if (nullIn >= 0) {
            dup2(nullIn, STDIN_FILENO);
            close(nullIn);
        }
        int nullOut = logPath.empty()
            ? open("/dev/null", O_WRONLY)
            : open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (nullOut >= 0) {
            dup2(nullOut, STDOUT_FILENO);
            dup2(nullOut, STDERR_FILENO);
            close(nullOut);
        }
        std::vector<char *> argv;
        for (const std::string &argument : arguments)
            argv.push_back(const_cast<char *>(argument.c_str()));
        argv.push_back(nullptr);
        execv(argv[0], argv.data());
        _exit(127);
    }
    return {pid};
}

static void stopProcess(ChildProcess &process) {
    if (process.pid <= 0) return;
    kill(process.pid, SIGTERM);
    int status = 0;
    waitpid(process.pid, &status, 0);
    process.pid = -1;
}

static bool waitForListener(int port) {
    for (int attempt = 0; attempt < 200; ++attempt) {
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
    require(fd >= 0, "connect failed");
    std::string response;
    require(sendFrame(fd, "C\t" + std::to_string(session) + "\t" + command),
            "send failed");
    require(receiveFrame(fd, response), "receive failed");
    close(fd);
    std::size_t tab = response.rfind('\t');
    require(tab != std::string::npos, "response missing session suffix: " + response);
    u64 returnedSession = static_cast<u64>(std::stoull(response.substr(tab + 1)));
    response.resize(tab);
    return {response, returnedSession};
}

static std::pair<std::string, u64> eventuallyRequest(
    int port, u64 session, const std::string &command,
    const std::string &expectedPrefix) {
    std::pair<std::string, u64> result;
    for (int attempt = 0; attempt < 120; ++attempt) {
        result = request(port, session, command);
        if (result.first.rfind(expectedPrefix, 0) == 0) return result;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return result;
}

static void cleanup(ChildProcess &lb, ChildProcess (&nodes)[3],
                    const std::vector<std::string> &paths) {
    stopProcess(lb);
    for (auto &node : nodes) stopProcess(node);
    for (const auto &path : paths) unlink(path.c_str());
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;

    int ports[3];
    int lbPort = unusedPort();
    for (int index = 0; index < 3; ++index) {
        ports[index] = unusedPort();
        if (ports[index] < 0 || lbPort < 0) {
            std::cout << "tracker lb integration tests skipped: local sockets unavailable\n";
            return 77;
        }
        for (int earlier = 0; earlier < index; ++earlier)
            while (ports[index] == ports[earlier] || ports[index] == lbPort)
                ports[index] = unusedPort();
    }
    const int writePort = ports[0], readPortA = ports[1], readPortB = ports[2];

    std::string prefix = "/tmp/torrent-tracker-lb-integration-" +
                         std::to_string(getpid());
    std::string trackerInfo = prefix + "-trackers.txt";
    std::string lbInfo = prefix + "-lb.txt";
    std::string lbLog = prefix + "-lb.log";
    {
        std::ofstream output(trackerInfo);
        for (int port : ports) output << "127.0.0.1:" << port << '\n';
    }
    {
        std::ofstream output(lbInfo);
        output << "127.0.0.1:" << lbPort << '\n';
        for (int port : ports) output << "127.0.0.1:" << port << '\n';
    }

    ChildProcess nodes[3], lb;
    try {
        for (int index = 0; index < 3; ++index)
            nodes[index] = startProcess({argv[1], trackerInfo, std::to_string(index + 1)});
        for (int port : ports) require(waitForListener(port), "tracker did not start");

        lb = startProcess({argv[2], lbInfo}, lbLog);
        require(waitForListener(lbPort), "load balancer did not start");

        require(eventuallyRequest(lbPort, 0, "create_user alice secret", "OK").first ==
                    "OK user created",
                "create_user did not succeed through load balancer");
        auto aliceLogin = request(lbPort, 0, "login alice secret");
        require(aliceLogin.first == "OK logged in", "login failed");
        require(aliceLogin.second != 0, "login did not return a session");

        require(request(lbPort, aliceLogin.second, "create_group demo").first ==
                    "OK group created",
                "post-login create_group failed");
        auto groups = request(lbPort, aliceLogin.second, "list_groups");
        require(groups.first.find("demo") != std::string::npos,
                "read after write through load balancer lost the write");

        std::string encodedName = hexEncode("notes.txt");
        std::string upload =
            "upload_file demo " + encodedName + " 0 "
            "0123456789abcdef0123456789abcdef01234567 "
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
            "- 127.0.0.1 9000";
        require(request(lbPort, aliceLogin.second, upload).first ==
                    "OK file shared "
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "upload metadata failed");
        auto files = request(lbPort, aliceLogin.second, "list_files demo");
        require(files.first.find(encodedName) != std::string::npos,
                "state-changing command was not immediately readable");

        // Both read servers hold every acknowledged write.
        for (int port : {readPortA, readPortB}) {
            auto replicated = eventuallyRequest(port, aliceLogin.second, "list_files demo",
                                                "OK " + encodedName);
            require(replicated.first == "OK " + encodedName,
                    "write did not reach a read server");
        }

        // One read server down: reads and writes keep working.
        stopProcess(nodes[1]);
        require(request(lbPort, aliceLogin.second, "create_group onedown").first ==
                    "OK group created",
                "write failed with one read server down");
        for (int attempt = 0; attempt < 4; ++attempt)
            require(request(lbPort, aliceLogin.second, "list_groups").first ==
                        "OK demo onedown",
                    "read failed with one read server down");
        nodes[1] = startProcess({argv[1], trackerInfo, "2"});
        require(waitForListener(readPortA), "read server did not restart");
        require(eventuallyRequest(readPortA, aliceLogin.second, "list_groups",
                                  "OK demo onedown").first == "OK demo onedown",
                "restarted read server was not caught up");

        // Write server down: reads still served, writes refused.
        stopProcess(nodes[0]);
        require(request(lbPort, aliceLogin.second, "list_files demo").first.find(
                    encodedName) != std::string::npos,
                "reads failed with the write server down");
        require(request(lbPort, aliceLogin.second, "create_group nowriter").first ==
                    "ERR write server unavailable",
                "write did not fail cleanly without the write server");

        // Write server restarts, recovers from the read servers, accepts writes.
        nodes[0] = startProcess({argv[1], trackerInfo, "1"});
        require(waitForListener(writePort), "write server did not restart");
        require(eventuallyRequest(lbPort, aliceLogin.second, "create_group afterfail",
                                  "OK").first == "OK group created",
                "recovered write server did not accept a write");
        require(request(lbPort, aliceLogin.second, "list_groups").first ==
                    "OK afterfail demo onedown",
                "recovered write server lost earlier writes");

        for (auto &node : nodes) stopProcess(node);
        auto unavailable = request(lbPort, aliceLogin.second, "list_groups");
        require(unavailable.first == "ERR tracker service unavailable",
                "LB did not report all trackers unavailable");
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        cleanup(lb, nodes, {trackerInfo, lbInfo, lbLog});
        return 1;
    }

    stopProcess(lb);
    {
        std::ifstream input(lbLog);
        std::string logs((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        if (logs.find("secret") != std::string::npos) {
            std::cerr << "load balancer log leaked a password\n";
            cleanup(lb, nodes, {trackerInfo, lbInfo, lbLog});
            return 1;
        }
    }
    cleanup(lb, nodes, {trackerInfo, lbInfo, lbLog});
    std::cout << "tracker lb integration tests passed\n";
    return 0;
}

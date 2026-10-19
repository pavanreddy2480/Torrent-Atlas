#include "../common/net.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cassert>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

static int unusedPort() {
    Socket socket(::socket(AF_INET, SOCK_STREAM, 0));
    if (!socket) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    if (bind(socket.fd(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
        getsockname(socket.fd(), reinterpret_cast<sockaddr *>(&address), &length) != 0)
        return -1;
    return ntohs(address.sin_port);
}

static std::string request(const std::string &payload, int port) {
    Socket socket = Socket::connect({"127.0.0.1", port});
    assert(socket);
    std::string response;
    assert(socket.sendFrame(payload));
    assert(socket.receiveFrame(response));
    return response;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int peerPort = unusedPort();
    int lbPort = unusedPort();
    if (peerPort < 0 || lbPort < 0) return 77;
    std::string config = "/tmp/torrent-peer-rejection-" +
                         std::to_string(getpid()) + ".conf";
    {
        std::ofstream output(config);
        output << "127.0.0.1:" << lbPort << '\n' << std::string(64, '0') << '\n';
    }
    int inputPipe[2];
    assert(pipe(inputPipe) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        dup2(inputPipe[0], STDIN_FILENO);
        close(inputPipe[0]);
        close(inputPipe[1]);
        int nullOutput = open("/dev/null", O_WRONLY);
        if (nullOutput >= 0) {
            dup2(nullOutput, STDOUT_FILENO);
            dup2(nullOutput, STDERR_FILENO);
            close(nullOutput);
        }
        std::string endpoint = "127.0.0.1:" + std::to_string(peerPort);
        execl(argv[1], argv[1], endpoint.c_str(), config.c_str(),
              static_cast<char *>(nullptr));
        _exit(127);
    }
    close(inputPipe[0]);
    bool listening = false;
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (Socket::connect({"127.0.0.1", peerPort}, 1)) {
            listening = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    if (!listening) {
        kill(child, SIGTERM);
        waitpid(child, nullptr, 0);
        close(inputPipe[1]);
        unlink(config.c_str());
        return 1;
    }
    assert(request("not-a-secure-message", peerPort).rfind("60|", 0) == 0);
    std::string unknown =
        "21|64656d6f|66696c65|000000000000000000000000|00|"
        "00000000000000000000000000000000";
    assert(request(unknown, peerPort).rfind("60|unauthorized", 0) == 0);

    kill(child, SIGTERM);
    waitpid(child, nullptr, 0);
    close(inputPipe[1]);
    unlink(config.c_str());
    std::cout << "peer rejection tests passed\n";
}

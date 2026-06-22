#include "../common/protocol.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <vector>

struct ChildProcess {
    pid_t pid = -1;
    int input = -1;
    int output = -1;
    std::string received;
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
                                 bool captureOutput) {
    int inputPipe[2]{};
    int outputPipe[2]{};
    require(pipe(inputPipe) == 0, "stdin pipe failed");
    require(!captureOutput || pipe(outputPipe) == 0, "stdout pipe failed");
    pid_t pid = fork();
    require(pid >= 0, "fork failed");
    if (pid == 0) {
        dup2(inputPipe[0], STDIN_FILENO);
        close(inputPipe[0]);
        close(inputPipe[1]);
        if (captureOutput) {
            dup2(outputPipe[1], STDOUT_FILENO);
            dup2(outputPipe[1], STDERR_FILENO);
            close(outputPipe[0]);
            close(outputPipe[1]);
        } else {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) {
                dup2(nullFd, STDOUT_FILENO);
                dup2(nullFd, STDERR_FILENO);
                close(nullFd);
            }
        }
        std::vector<char *> argv;
        for (const std::string &argument : arguments)
            argv.push_back(const_cast<char *>(argument.c_str()));
        argv.push_back(nullptr);
        execv(argv[0], argv.data());
        _exit(127);
    }
    close(inputPipe[0]);
    if (captureOutput) close(outputPipe[1]);
    return {pid, inputPipe[1], captureOutput ? outputPipe[0] : -1, ""};
}

static void stopProcess(ChildProcess &process) {
    if (process.input >= 0) {
        close(process.input);
        process.input = -1;
    }
    if (process.output >= 0) {
        close(process.output);
        process.output = -1;
    }
    if (process.pid > 0) {
        kill(process.pid, SIGTERM);
        int status = 0;
        waitpid(process.pid, &status, 0);
        process.pid = -1;
    }
}

static bool waitForListener(int port, int seconds = 20) {
    int attempts = seconds * 20;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        int fd = connectTcp("127.0.0.1", port, 1);
        if (fd >= 0) {
            close(fd);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

static bool waitForOutput(ChildProcess &process, const std::string &expected,
                          int seconds = 20) {
    int attempts = seconds * 20;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (process.received.find(expected) != std::string::npos) return true;
        pollfd descriptor{process.output, POLLIN, 0};
        int ready = poll(&descriptor, 1, 50);
        if (ready > 0 && (descriptor.revents & POLLIN)) {
            char buffer[4096];
            ssize_t count = read(process.output, buffer, sizeof(buffer));
            if (count > 0) process.received.append(buffer, static_cast<std::size_t>(count));
        }
    }
    return process.received.find(expected) != std::string::npos;
}

static void command(ChildProcess &process, const std::string &line,
                    const std::string &expected) {
    process.received.clear();
    std::string input = line + "\n";
    std::size_t written = 0;
    while (written < input.size()) {
        ssize_t count = write(process.input, input.data() + written,
                              input.size() - written);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "failed to write client command");
        written += static_cast<std::size_t>(count);
    }
    require(waitForOutput(process, expected),
            "command failed: " + line + "\noutput: " + process.received);
}

static std::string fileName(const std::string &path) {
    std::size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

static bool filesEqual(const std::string &left, const std::string &right) {
    std::ifstream first(left, std::ios::binary);
    std::ifstream second(right, std::ios::binary);
    std::vector<char> firstBuffer(65536), secondBuffer(65536);
    for (;;) {
        first.read(firstBuffer.data(), static_cast<std::streamsize>(firstBuffer.size()));
        second.read(secondBuffer.data(), static_cast<std::streamsize>(secondBuffer.size()));
        if (first.gcount() != second.gcount()) return false;
        if (!std::equal(firstBuffer.begin(), firstBuffer.begin() + first.gcount(),
                        secondBuffer.begin()))
            return false;
        if (first.eof() || second.eof()) return first.eof() && second.eof();
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int trackerOnePort = unusedPort();
    int trackerTwoPort = unusedPort();
    int seederPort = unusedPort();
    int downloaderPort = unusedPort();
    if (trackerOnePort < 0 || trackerTwoPort < 0 ||
        seederPort < 0 || downloaderPort < 0) {
        std::cout << "client integration tests skipped: local sockets unavailable\n";
        return 77;
    }

    std::string prefix = "/tmp/torrent-client-integration-" +
                         std::to_string(getpid());
    std::string trackerInfo = prefix + "-trackers.txt";
    std::string source = prefix + "-source.bin";
    std::string destination = prefix + "-copy.bin";
    {
        std::ofstream output(trackerInfo);
        output << "127.0.0.1:" << trackerOnePort << '\n'
               << "127.0.0.1:" << trackerTwoPort << '\n';
    }
    {
        std::ofstream output(source, std::ios::binary);
        for (std::size_t index = 0; index < PIECE_SIZE * 2 + 12345; ++index)
            output.put(static_cast<char>((index * 31U + 17U) & 0xffU));
    }

    ChildProcess trackerOne, trackerTwo, seeder, downloader;
    try {
        trackerOne = startProcess({argv[1], trackerInfo, "1"}, false);
        trackerTwo = startProcess({argv[1], trackerInfo, "2"}, false);
        require(waitForListener(trackerOnePort), "tracker one did not start");
        require(waitForListener(trackerTwoPort), "tracker two did not start");

        seeder = startProcess({
            argv[2], "127.0.0.1:" + std::to_string(seederPort), trackerInfo}, true);
        downloader = startProcess({
            argv[2], "127.0.0.1:" + std::to_string(downloaderPort), trackerInfo}, true);
        require(waitForListener(seederPort), "seeder did not start");
        require(waitForListener(downloaderPort), "downloader did not start");

        command(seeder, "create user alice secret", "OK user created");
        command(seeder, "login alice secret", "OK logged in");
        command(seeder, "create group demo", "OK group created");
        command(seeder, "upload file demo \"" + source + "\"", "OK file shared");

        command(downloader, "create user bob secret", "OK user created");
        command(downloader, "login bob secret", "OK logged in");
        command(downloader, "join group demo", "OK join requested");
        command(seeder, "accept request demo bob", "OK request accepted");
        command(downloader, "download file demo " + fileName(source) +
                            " \"" + destination + "\"", "OK download started");

        bool completed = false;
        for (int attempt = 0; attempt < 600; ++attempt) {
            struct stat info{};
            if (stat(destination.c_str(), &info) == 0 &&
                static_cast<std::size_t>(info.st_size) == PIECE_SIZE * 2 + 12345) {
                completed = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        require(completed, "download did not complete");
        require(filesEqual(source, destination), "downloaded file differs from source");

        command(downloader, "show downloads", "[C]");
        std::cout << "client integration tests passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        stopProcess(downloader);
        stopProcess(seeder);
        stopProcess(trackerTwo);
        stopProcess(trackerOne);
        unlink(trackerInfo.c_str());
        unlink(source.c_str());
        unlink(destination.c_str());
        unlink((destination + ".part").c_str());
        unlink((destination + ".resume").c_str());
        return 1;
    }

    stopProcess(downloader);
    stopProcess(seeder);
    stopProcess(trackerTwo);
    stopProcess(trackerOne);
    unlink(trackerInfo.c_str());
    unlink(source.c_str());
    unlink(destination.c_str());
    return 0;
}

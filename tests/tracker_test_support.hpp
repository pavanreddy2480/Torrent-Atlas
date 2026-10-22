#pragma once

// Starts and talks to a local tracker process for integration tests.

#include "common/config/client_config.hpp"
#include "common/config/tracker_identity.hpp"
#include "common/encoding.hpp"
#include "common/net/secure_channel.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <stdexcept>
#include <thread>

namespace tracker_test {

inline int unusedPort() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = sizeof(address);
    int port = -1;
    if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 &&
        getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) == 0)
        port = ntohs(address.sin_port);
    close(fd);
    return port;
}

inline bool waitForListener(int port) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        if (Socket::connect({"127.0.0.1", port}, 1)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

struct Response {
    std::string text;
    u64 session = 0;
};

class TrackerProcess {
public:
    Endpoint address;
    std::string keys, dataDir, clientConf, publicKey;

    // Returns false if local sockets are unavailable.
    bool setup(const std::string &trackerBinary, const std::string &dir) {
        binary_ = trackerBinary;
        ::mkdir(dir.c_str(), 0700);
        keys = dir + "/keys";
        dataDir = dir + "/data";
        clientConf = dir + "/client.conf";
        int port = unusedPort();
        if (port < 0) return false;
        address = {"127.0.0.1", port};
        std::string error;
        if (!TrackerIdentity::create(address, keys, clientConf, error))
            throw std::runtime_error("tracker setup failed: " + error);
        publicKey = ClientConfig::load(clientConf)->trackerPublicKey;
        return true;
    }

    void start() {
        pid_t pid = fork();
        if (pid < 0) throw std::runtime_error("fork failed");
        if (pid == 0) {
            int nullIn = open("/dev/null", O_RDONLY);
            int nullOut = open("/dev/null", O_WRONLY);
            dup2(nullIn, STDIN_FILENO);
            dup2(nullOut, STDOUT_FILENO);
            dup2(nullOut, STDERR_FILENO);
            std::string listen = address.toString();
            execl(binary_.c_str(), binary_.c_str(), listen.c_str(), keys.c_str(), dataDir.c_str(),
                  static_cast<char *>(nullptr));
            _exit(127);
        }
        pid_ = pid;
        if (!waitForListener(address.port)) throw std::runtime_error("tracker did not start");
    }

    void stop() {
        if (pid_ <= 0) return;
        kill(pid_, SIGKILL);   // a crash, not a clean shutdown
        waitpid(pid_, nullptr, 0);
        pid_ = -1;
    }

    // One request, as the client sends it. False if the tracker can't be
    // reached or authenticated under pinnedKey.
    bool request(u64 session, const std::string &command, Response &out,
                 const std::string &pinnedKey = "") {
        std::string response;
        if (!callTracker(address, pinnedKey.empty() ? publicKey : pinnedKey,
                         "C\t" + std::to_string(session) + "\t" + command, response))
            return false;
        std::size_t tab = response.rfind('\t');
        out.text = response.substr(0, tab);
        out.session = tab == std::string::npos ? 0 : std::stoull(response.substr(tab + 1));
        return true;
    }

    Response request(u64 session, const std::string &command) {
        Response out{"ERR no answer", session};
        request(session, command, out);
        return out;
    }

    ~TrackerProcess() { stop(); }

private:
    std::string binary_;
    pid_t pid_ = -1;
};

}  // namespace tracker_test

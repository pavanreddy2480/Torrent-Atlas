#pragma once

// Starts and talks to a local 3-node tracker cluster for integration tests.

#include "../common/cluster_keys.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>

namespace cluster_test {

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
        UniqueFd fd(connectTcp("127.0.0.1", port, 1));
        if (fd) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

struct Response {
    std::string text;
    u64 session = 0;
};

class Cluster {
    std::string tracker_;
    std::string dir_;
    std::vector<pid_t> pids_;

public:
    std::vector<ClusterMember> members;
    std::string conf, keys, clientConf, publicKey;

    // Returns false if local sockets are unavailable.
    bool setup(const std::string &trackerBinary, const std::string &dir) {
        tracker_ = trackerBinary;
        dir_ = dir;
        ::mkdir(dir_.c_str(), 0700);
        conf = dir_ + "/cluster.conf";
        keys = dir_ + "/keys";
        clientConf = dir_ + "/client.conf";
        std::vector<int> ports;
        while (ports.size() < 6) {
            int port = unusedPort();
            if (port < 0) return false;
            if (std::find(ports.begin(), ports.end(), port) == ports.end()) ports.push_back(port);
        }
        {
            std::ofstream output(conf);
            for (int id = 1; id <= 3; ++id)
                output << id << " 127.0.0.1:" << ports[id - 1] << " 127.0.0.1:"
                       << ports[id + 2] << '\n';
        }
        std::string error;
        if (!readClusterConfig(conf, members) ||
            !generateClusterKeys(members, keys, clientConf, error))
            throw std::runtime_error("cluster setup failed: " + error);
        std::ifstream input(clientConf);
        std::string token, last;
        while (input >> token) last = token;
        hexDecode(last, publicKey);
        pids_.assign(members.size(), -1);
        return true;
    }

    int clientPort(std::size_t node) const { return members[node].client.port; }

    void start(std::size_t node, bool quiet = true) {
        std::string id = std::to_string(members[node].id);
        std::string data = dir_ + "/data" + id;
        pid_t pid = fork();
        if (pid < 0) throw std::runtime_error("fork failed");
        if (pid == 0) {
            int nullIn = open("/dev/null", O_RDONLY);
            dup2(nullIn, STDIN_FILENO);
            if (quiet) {
                int nullOut = open("/dev/null", O_WRONLY);
                dup2(nullOut, STDOUT_FILENO);
                dup2(nullOut, STDERR_FILENO);
            }
            execl(tracker_.c_str(), tracker_.c_str(), conf.c_str(), id.c_str(), keys.c_str(),
                  data.c_str(), static_cast<char *>(nullptr));
            _exit(127);
        }
        pids_[node] = pid;
        if (!waitForListener(clientPort(node)))
            throw std::runtime_error("tracker " + id + " did not start");
    }

    void stop(std::size_t node) {
        if (pids_[node] <= 0) return;
        kill(pids_[node], SIGKILL);   // a crash, not a clean shutdown
        waitpid(pids_[node], nullptr, 0);
        pids_[node] = -1;
    }

    void startAll() { for (std::size_t i = 0; i < members.size(); ++i) start(i); }
    void stopAll() { for (std::size_t i = 0; i < members.size(); ++i) stop(i); }

    // One request to one node, without following redirects.
    bool requestTo(std::size_t node, u64 session, const std::string &command, Response &out,
                   const std::string &pinnedKey = "") {
        std::string response;
        if (!secureTrackerCall(members[node].client, pinnedKey.empty() ? publicKey : pinnedKey,
                               "C\t" + std::to_string(session) + "\t" + command, response))
            return false;
        std::size_t tab = response.rfind('\t');
        out.text = response.substr(0, tab);
        out.session = tab == std::string::npos ? 0 : std::stoull(response.substr(tab + 1));
        return true;
    }

    // Like the real client: find the leader, retry during elections.
    Response request(u64 session, const std::string &command, int attempts = 40) {
        Response out{"ERR no answer", session};
        for (int attempt = 0; attempt < attempts; ++attempt) {
            for (std::size_t node = 0; node < members.size(); ++node) {
                if (pids_[node] <= 0) continue;
                if (!requestTo(node, session, command, out)) continue;
                if (out.text.rfind("REDIRECT", 0) == 0) continue;
                if (out.text.rfind("ERR no leader", 0) == 0 ||
                    out.text.rfind("ERR write not committed", 0) == 0)
                    break;
                return out;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        return out;
    }

    // Index of the node that currently answers instead of redirecting.
    int leader() {
        for (int attempt = 0; attempt < 60; ++attempt) {
            for (std::size_t node = 0; node < members.size(); ++node) {
                Response out;
                if (pids_[node] > 0 && requestTo(node, 0, "list_groups", out) &&
                    out.text.rfind("REDIRECT", 0) != 0 && out.text.rfind("ERR no leader", 0) != 0)
                    return static_cast<int>(node);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return -1;
    }

    ~Cluster() { stopAll(); }
};

}  // namespace cluster_test

#include "../common/secure_channel.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Load balancer for one write server and two read servers.
//   writes -> write server only
//   reads  -> round-robin over read servers that have applied everything the
//             write server has; the write server itself if none are in sync;
//             the most up-to-date read server if the write server is down.

struct NodeStatus {
    bool reachable = false;
    bool ready = false;
    u64 sequence = 0;
};

bool readLbInfo(const std::string &path, Endpoint &listen,
                std::array<Endpoint, 3> &backends) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<Endpoint> endpoints;
    std::string token;
    while (input >> token) {
        Endpoint endpoint;
        if (!parseEndpoint(token, endpoint)) return false;
        endpoints.push_back(endpoint);
    }
    if (endpoints.size() != 4) return false;
    listen = endpoints[0];
    backends = {endpoints[1], endpoints[2], endpoints[3]};
    for (std::size_t i = 0; i < endpoints.size(); ++i)
        for (std::size_t j = i + 1; j < endpoints.size(); ++j)
            if (endpointKey(endpoints[i]) == endpointKey(endpoints[j])) return false;
    return true;
}

class LoadBalancer {
    static constexpr std::size_t WRITER = 0;
    Endpoint listen_;
    std::string clusterKey_;
    std::string identityKey_;
    std::array<Endpoint, 3> backends_;
    std::atomic<std::size_t> nextReader_{0};

    NodeStatus queryStatus(std::size_t backend) const {
        NodeStatus status;
        std::string response;
        if (!clusterCall(backends_[backend], clusterKey_, "X\t0\tSTATUS", response)) return status;
        std::vector<std::string> fields = split(response, '\t');
        if (fields.size() != 4 || fields[0] != "STATUS" ||
            !parseUnsignedDecimal(fields[2], status.sequence))
            return status;
        status.reachable = true;
        status.ready = fields[3] == "READY";
        return status;
    }

    std::vector<std::size_t> readOrder() {
        std::array<NodeStatus, 3> status = {queryStatus(0), queryStatus(1), queryStatus(2)};
        std::vector<std::size_t> readers;
        std::size_t start = nextReader_++ % 2;
        for (std::size_t offset = 0; offset < 2; ++offset) {
            std::size_t reader = 1 + (start + offset) % 2;
            if (status[reader].reachable) readers.push_back(reader);
        }
        const NodeStatus &writer = status[WRITER];
        if (writer.reachable && writer.ready) {
            std::vector<std::size_t> order;
            for (std::size_t reader : readers)
                if (status[reader].sequence == writer.sequence) order.push_back(reader);
            order.push_back(WRITER);
            return order;
        }
        // No write server: nothing newer than the best read server exists.
        std::stable_sort(readers.begin(), readers.end(), [&](std::size_t a, std::size_t b) {
            return status[a].sequence > status[b].sequence;
        });
        return readers;
    }

    bool forward(std::size_t backend, const std::string &request,
                 std::string &response) const {
        return clusterCall(backends_[backend], clusterKey_, request, response);
    }

    void handleClient(int rawFd) {
        UniqueFd fd(rawFd);
        timeval timeout{};
        timeout.tv_sec = 5;
        setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        // Plain-text or badly signed hellos never get past this point.
        std::string sessionKey, request;
        if (!serverHandshake(fd.get(), identityKey_, sessionKey) ||
            !sealedReceive(fd.get(), sessionKey, "client->lb", request)) {
            secureErase(sessionKey);
            return;
        }
        auto reply = [&](const std::string &text) {
            sealedSend(fd.get(), sessionKey, "lb->client", text);
            secureErase(sessionKey);
        };
        std::vector<std::string> fields = split(request, '\t');
        u64 session = 0;
        bool sessionParseable = fields.size() >= 3 && fields[0] == "C" &&
                                parseUnsignedDecimal(fields[1], session);
        if (!sessionParseable) {
            // Clients may only send commands; cluster-internal frames are refused.
            reply("ERR malformed request\t0");
            return;
        }
        bool write = isTrackerMutation(fields[2]);

        std::vector<std::size_t> order = write ? std::vector<std::size_t>{WRITER}
                                               : readOrder();
        for (std::size_t backend : order) {
            std::string response;
            if (forward(backend, request, response)) {
                reply(response);
                return;
            }
            std::cerr << "tracker_lb: backend " << (backend + 1)
                      << " unavailable\n";
        }
        std::string response = write ? "ERR write server unavailable"
                                      : "ERR tracker service unavailable";
        reply(response + "\t" + std::to_string(session));
    }

public:
    LoadBalancer(Endpoint listen, std::array<Endpoint, 3> backends,
                 std::string clusterKey, std::string identityKey)
        : listen_(std::move(listen)), clusterKey_(std::move(clusterKey)),
          identityKey_(std::move(identityKey)), backends_(std::move(backends)) {}

    int run() {
        UniqueFd listener(createListener(listen_.ip, listen_.port));
        if (!listener) {
            perror("tracker_lb listen");
            return 1;
        }
        std::cerr << "tracker_lb listening on " << endpointKey(listen_)
                  << ", write server " << endpointKey(backends_[0])
                  << ", read servers " << endpointKey(backends_[1]) << " and "
                  << endpointKey(backends_[2]) << '\n';

        bool running = true;
        bool monitorConsole = true;
        std::mutex workersMutex;
        std::condition_variable workersCondition;
        std::size_t activeWorkers = 0;
        while (running) {
            pollfd descriptors[2]{{listener.get(), POLLIN, 0},
                                  {monitorConsole ? STDIN_FILENO : -1,
                                   POLLIN, 0}};
            int ready = poll(descriptors, 2, -1);
            if (ready < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (monitorConsole &&
                (descriptors[1].revents & (POLLIN | POLLHUP))) {
                std::string command;
                if (!std::getline(std::cin, command)) monitorConsole = false;
                else if (command == "quit") running = false;
            }
            if (!running) break;
            if (descriptors[0].revents & POLLIN) {
                int client = accept(listener.get(), nullptr, nullptr);
                if (client < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                {
                    std::lock_guard<std::mutex> lock(workersMutex);
                    ++activeWorkers;
                }
                std::thread([&, client] {
                    handleClient(client);
                    {
                        std::lock_guard<std::mutex> lock(workersMutex);
                        --activeWorkers;
                    }
                    workersCondition.notify_all();
                }).detach();
            }
        }
        listener.reset();
        std::unique_lock<std::mutex> lock(workersMutex);
        workersCondition.wait(lock, [&] { return activeWorkers == 0; });
        return 0;
    }
};

}  // namespace

int main(int argc, char **argv) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0]
                  << " load_balancer.conf cluster.key lb_identity.key\n";
        return 1;
    }
    Endpoint listen;
    std::array<Endpoint, 3> backends;
    if (!readLbInfo(argv[1], listen, backends)) {
        std::cerr << "LB config must list the listen address, the write server, and two read servers as IP:PORT entries\n";
        return 1;
    }
    std::string clusterKey, identityKey;
    if (!readKeyFile(argv[2], 32, clusterKey) || !readKeyFile(argv[3], 32, identityKey)) {
        std::cerr << "could not read the cluster key or LB identity key (run torrent_keygen)\n";
        return 1;
    }
    return LoadBalancer(std::move(listen), std::move(backends), std::move(clusterKey),
                        std::move(identityKey)).run();
}

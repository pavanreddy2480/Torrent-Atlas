#include "../common/protocol.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

struct Route {
    std::size_t owner = 0;
    u64 session = 0;
    bool sessionParseable = false;
    bool mutation = false;
};

struct BackendStatus {
    bool reachable = false;
    bool degraded = true;
    std::array<u64, 2> applied{};
};

std::uint64_t stableHash(const std::string &value) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool readLbInfo(const std::string &path, Endpoint &listen,
                std::array<Endpoint, 2> &backends) {
    std::ifstream input(path);
    if (!input) return false;
    std::vector<Endpoint> endpoints;
    std::string token;
    while (input >> token) {
        Endpoint endpoint;
        if (!parseEndpoint(token, endpoint)) return false;
        endpoints.push_back(endpoint);
    }
    if (endpoints.size() != 3) return false;
    listen = endpoints[0];
    backends = {endpoints[1], endpoints[2]};
    return endpointKey(listen) != endpointKey(backends[0]) &&
           endpointKey(listen) != endpointKey(backends[1]) &&
           endpointKey(backends[0]) != endpointKey(backends[1]);
}

Route chooseRoute(const std::string &request) {
    Route route;
    std::vector<std::string> fields = split(request, '\t');
    if (fields.size() < 3 || fields[0] != "C") return route;
    if (!parseUnsignedDecimal(fields[1], route.session)) return route;
    route.sessionParseable = true;

    std::string commandLine = fields[2];
    for (std::size_t index = 3; index < fields.size(); ++index)
        commandLine += "\t" + fields[index];
    std::istringstream input(commandLine);
    std::string command, key;
    input >> command >> key;

    static const std::unordered_set<std::string> mutations = {
        "create_user", "login", "logout", "create_group", "join_group",
        "leave_group", "accept_request", "upload_file", "stop_share"};
    static const std::unordered_set<std::string> groupCommands = {
        "create_group", "join_group", "leave_group", "list_requests",
        "accept_request", "upload_file", "list_files", "download_file",
        "stop_share"};
    route.mutation = mutations.count(command) != 0;

    if ((command == "create_user" || command == "login") && !key.empty()) {
        route.owner = static_cast<std::size_t>(stableHash(key) % 2U);
    } else if (groupCommands.count(command) && !key.empty()) {
        route.owner = static_cast<std::size_t>(stableHash(key) % 2U);
    } else if (route.session != 0) {
        std::uint8_t tag =
            static_cast<std::uint8_t>((route.session >> 56U) & 0xffU);
        if (tag == 1 || tag == 2)
            route.owner = static_cast<std::size_t>(tag - 1);
    }
    return route;
}

bool dominates(const BackendStatus &left, const BackendStatus &right) {
    return left.applied[0] >= right.applied[0] &&
           left.applied[1] >= right.applied[1];
}

class LoadBalancer {
    Endpoint listen_;
    std::array<Endpoint, 2> backends_;
    std::mutex mutationMutex_;

    BackendStatus queryStatus(std::size_t backend) const {
        BackendStatus status;
        UniqueFd fd(connectTcp(backends_[backend].ip,
                               backends_[backend].port, 2));
        if (!fd) return status;
        std::string response;
        if (!sendFrame(fd.get(), "X\t0\tSTATUS") ||
            !receiveFrame(fd.get(), response))
            return status;
        std::vector<std::string> fields = split(response, '\t');
        if (fields.size() != 4 || fields[0] != "STATUS" ||
            !parseUnsignedDecimal(fields[1], status.applied[0]) ||
            !parseUnsignedDecimal(fields[2], status.applied[1]) ||
            (fields[3] != "READY" && fields[3] != "DEGRADED"))
            return status;
        status.reachable = true;
        status.degraded = fields[3] == "DEGRADED";
        return status;
    }

    std::vector<std::size_t> backendOrder(std::size_t owner) const {
        std::array<BackendStatus, 2> status = {queryStatus(0), queryStatus(1)};
        bool usable0 = status[0].reachable && !status[0].degraded;
        bool usable1 = status[1].reachable && !status[1].degraded;
        if (!usable0 && !usable1) return {};
        if (usable0 && !usable1) return {0};
        if (!usable0 && usable1) return {1};
        if (status[0].applied == status[1].applied)
            return {owner, owner == 0 ? 1U : 0U};
        if (dominates(status[0], status[1])) return {0};
        if (dominates(status[1], status[0])) return {1};
        return {};
    }

    bool forward(std::size_t backend, const std::string &request,
                 std::string &response) const {
        UniqueFd fd(connectTcp(backends_[backend].ip,
                               backends_[backend].port, 2));
        return fd && sendFrame(fd.get(), request) &&
               receiveFrame(fd.get(), response);
    }

    void handleClient(int rawFd) {
        UniqueFd fd(rawFd);
        timeval timeout{};
        timeout.tv_sec = 5;
        setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        std::string request;
        if (!receiveFrame(fd.get(), request)) return;
        Route route = chooseRoute(request);
        std::unique_lock<std::mutex> mutationLock(mutationMutex_, std::defer_lock);
        if (route.mutation) mutationLock.lock();

        for (std::size_t backend : backendOrder(route.owner)) {
            std::string response;
            if (forward(backend, request, response)) {
                sendFrame(fd.get(), response);
                return;
            }
            std::cerr << "tracker_lb: backend " << (backend + 1)
                      << " unavailable\n";
        }
        std::string response = "ERR tracker service unavailable";
        if (route.sessionParseable)
            response += "\t" + std::to_string(route.session);
        sendFrame(fd.get(), response);
    }

public:
    LoadBalancer(Endpoint listen, std::array<Endpoint, 2> backends)
        : listen_(std::move(listen)), backends_(std::move(backends)) {}

    int run() {
        UniqueFd listener(createListener(listen_.ip, listen_.port));
        if (!listener) {
            perror("tracker_lb listen");
            return 1;
        }
        std::cerr << "tracker_lb listening on " << endpointKey(listen_)
                  << ", backends " << endpointKey(backends_[0]) << " and "
                  << endpointKey(backends_[1]) << '\n';

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
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " lb_info.txt\n";
        return 1;
    }
    Endpoint listen;
    std::array<Endpoint, 2> backends;
    if (!readLbInfo(argv[1], listen, backends)) {
        std::cerr << "LB config must contain listen, tracker-1, and tracker-2 IP:PORT entries\n";
        return 1;
    }
    return LoadBalancer(std::move(listen), std::move(backends)).run();
}

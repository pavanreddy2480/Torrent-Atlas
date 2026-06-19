#include "../common/protocol.hpp"

#include <cassert>
#include <iostream>

static std::string request(const std::string &payload, int port) {
    int fd = connectTcp("127.0.0.1", port);
    assert(fd >= 0);
    std::string response;
    assert(sendFrame(fd, payload));
    assert(receiveFrame(fd, response));
    close(fd);
    return response;
}

int main(int argc, char **argv) {
    int port = argc == 2 ? std::stoi(argv[1]) : 8201;
    assert(request("not-a-secure-message", port).rfind("60|", 0) == 0);
    std::string stale =
        "20|1|00000000000000000000000000000000|2|2|1|1";
    assert(request(stale, port).rfind("60|stale", 0) == 0);
    std::cout << "peer rejection tests passed\n";
}

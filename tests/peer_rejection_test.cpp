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
    std::string unknown =
        "21|64656d6f|66696c65|000000000000000000000000|00|"
        "00000000000000000000000000000000";
    assert(request(unknown, port).rfind("60|unauthorized", 0) == 0);
    std::cout << "peer rejection tests passed\n";
}

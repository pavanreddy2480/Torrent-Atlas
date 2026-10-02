#include "../common/protocol.hpp"

#include <cassert>
#include <iostream>
#include <sys/socket.h>

int main() {
    Endpoint endpoint;
    assert(parseEndpoint("127.0.0.1:5000", endpoint));
    assert(endpoint.ip == "127.0.0.1" && endpoint.port == 5000);
    assert(!parseEndpoint("127.0.0.1:5000junk", endpoint));
    assert(!parseEndpoint("127.0.0.1:+5000", endpoint));
    assert(!parseEndpoint("127.0.0.1:0", endpoint));
    assert(!parseEndpoint("127.0.0.1:65536", endpoint));
    assert(!parseEndpoint("localhost:5000", endpoint));
    assert(!parseEndpoint("127.0.0.1:5000:7", endpoint));

    u64 value = 0;
    assert(parseUnsignedDecimal("0", value) && value == 0);
    assert(parseUnsignedDecimal("18446744073709551615", value));
    assert(!parseUnsignedDecimal("18446744073709551616", value));
    assert(!parseUnsignedDecimal("1x", value));
    assert(!parseUnsignedDecimal("", value));

    std::size_t pieces = 99;
    assert(pieceCountForSize(0, pieces) && pieces == 0);
    assert(pieceCountForSize(1, pieces) && pieces == 1);
    assert(pieceCountForSize(PIECE_SIZE, pieces) && pieces == 1);
    assert(pieceCountForSize(PIECE_SIZE + 1, pieces) && pieces == 2);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    UniqueFd first(sockets[0]), second(sockets[1]);
    assert(sendFrame(first.get(), "hello"));
    std::string payload;
    assert(receiveFrame(second.get(), payload) && payload == "hello");
    u32 oversized = htonl(static_cast<u32>(MAX_FRAME + 1));
    assert(writeExact(first.get(), &oversized, sizeof(oversized)));
    assert(!receiveFrame(second.get(), payload));
    assert(!sendFrame(first.get(), std::string(MAX_FRAME + 1, 'x')));

    std::cout << "protocol tests passed\n";
}

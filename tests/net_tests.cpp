#include "../common/encoding.hpp"
#include "../common/file_metadata.hpp"
#include "../common/net.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <iostream>
#include <sys/socket.h>

int main() {
    std::optional<Endpoint> endpoint = Endpoint::parse("127.0.0.1:5000");
    assert(endpoint && endpoint->ip == "127.0.0.1" && endpoint->port == 5000);
    assert(endpoint->toString() == "127.0.0.1:5000");
    for (const char *bad : {"127.0.0.1:5000junk", "127.0.0.1:+5000", "127.0.0.1:0",
                            "127.0.0.1:65536", "localhost:5000", "127.0.0.1:5000:7", ":5000"})
        assert(!Endpoint::parse(bad));

    u64 value = 0;
    assert(parseU64("0", value) && value == 0);
    assert(parseU64("18446744073709551615", value));
    assert(!parseU64("18446744073709551616", value));
    assert(!parseU64("1x", value));
    assert(!parseU64("-1", value));
    assert(!parseU64("", value));

    std::string bytes;
    assert(toHex("\x01\xab") == "01ab");
    assert(fromHex("01AB", bytes) && bytes == "\x01\xab");
    assert(!fromHex("0", bytes) && !fromHex("zz", bytes));
    assert(isHex("abc", 3) && !isHex("abz", 3) && !isHex("abc", 4));
    assert(split("a,,b", ',') == (std::vector<std::string>{"a", "", "b"}));
    assert(join({"a", "b"}, ',') == "a,b");

    assert(pieceCountForSize(0) == 0);
    assert(pieceCountForSize(1) == 1);
    assert(pieceCountForSize(PIECE_SIZE) == 1);
    assert(pieceCountForSize(PIECE_SIZE + 1) == 2);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    Socket first(sockets[0]), second(sockets[1]);
    std::string payload;
    assert(first.sendFrame("hello"));
    assert(second.receiveFrame(payload) && payload == "hello");
    assert(first.sendFrame(""));
    assert(second.receiveFrame(payload) && payload.empty());
    std::uint32_t oversized = htonl(static_cast<std::uint32_t>(Socket::MAX_FRAME + 1));
    assert(first.sendAll(&oversized, sizeof(oversized)));
    assert(!second.receiveFrame(payload));
    assert(!first.sendFrame(std::string(Socket::MAX_FRAME + 1, 'x')));

    std::cout << "net tests passed\n";
}

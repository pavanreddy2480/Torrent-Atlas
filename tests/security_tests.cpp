#include "../common/protocol.hpp"
#include "../common/secure_channel.hpp"
#include "../common/sha1.hpp"

#include <cassert>
#include <iostream>
#include <sys/socket.h>
#include <thread>

int main() {
    Sha1 emptySha1;
    assert(emptySha1.finalHex() ==
           "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    Sha1 abcSha1;
    abcSha1.update("abc", 3);
    assert(abcSha1.finalHex() ==
           "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert(hexEncode(pbkdf2HmacSha256("password", "salt", 1, 32)) ==
           "120fb6cffcf8b32c43e7225256c4f837"
           "a86548c92ccc35480805987cb70be17b");
    assert(isHexInteger("abc", 1, 3));
    assert(!isHexInteger("abz", 1, 3));

    std::string key = randomBytes(32);
    assert(key.size() == 32);
    AesGcmMessage message;
    assert(aes256GcmEncrypt(
        key, "21|group|file", "GET\n3", message));
    assert(message.nonce.size() == 12);
    assert(message.tag.size() == 16);
    std::string recovered;
    assert(aes256GcmDecrypt(
        key, "21|group|file", message, recovered));
    assert(recovered == "GET\n3");

    AesGcmMessage tampered = message;
    tampered.tag[0] ^= 1;
    assert(!aes256GcmDecrypt(key, "21|group|file", tampered, recovered));
    tampered = message;
    tampered.ciphertext[0] ^= 1;
    assert(!aes256GcmDecrypt(key, "21|group|file", tampered, recovered));
    tampered = message;
    tampered.nonce[0] ^= 1;
    assert(!aes256GcmDecrypt(key, "21|group|file", tampered, recovered));
    assert(!aes256GcmDecrypt(key, "21|other|file", message, recovered));
    std::string wrongKey = key;
    wrongKey[0] ^= 1;
    assert(!aes256GcmDecrypt(wrongKey, "21|group|file", message, recovered));

    AesGcmMessage empty;
    assert(aes256GcmEncrypt(key, "header", "", empty));
    assert(aes256GcmDecrypt(key, "header", empty, recovered));
    assert(recovered.empty());

    // SHA-256 / HMAC known answers.
    assert(hexEncode(sha256("abc")) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert(hexEncode(hmacSha256(std::string(20, '\x0b'), "Hi There")) ==
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // Ed25519: a signature verifies only for the same key and message.
    std::string signPrivate, signPublic, otherPrivate, otherPublic;
    assert(ed25519KeyPair(signPrivate, signPublic));
    assert(ed25519KeyPair(otherPrivate, otherPublic));
    std::string signature = ed25519Sign(signPrivate, "transcript");
    assert(signature.size() == 64);
    assert(ed25519Verify(signPublic, "transcript", signature));
    assert(!ed25519Verify(signPublic, "transcripT", signature));
    assert(!ed25519Verify(otherPublic, "transcript", signature));
    std::string badSignature = signature;
    badSignature[0] ^= 1;
    assert(!ed25519Verify(signPublic, "transcript", badSignature));

    // X25519: both sides derive the same secret.
    std::string aPrivate, aPublic, bPrivate, bPublic;
    assert(x25519KeyPair(aPrivate, aPublic) && x25519KeyPair(bPrivate, bPublic));
    std::string shared = x25519SharedSecret(aPrivate, bPublic);
    assert(shared.size() == 32 && shared == x25519SharedSecret(bPrivate, aPublic));

    // Client handshake over a socket pair: the right pinned key yields the
    // same session key on both sides; a wrong pinned key fails.
    auto handshake = [&](const std::string &pinned, std::string &clientKey,
                         std::string &serverKey) {
        int fds[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        bool serverOk = false;
        std::thread server([&] { serverOk = serverHandshake(fds[1], signPrivate, serverKey); });
        bool clientOk = clientHandshake(fds[0], pinned, clientKey);
        close(fds[0]);
        server.join();
        close(fds[1]);
        return clientOk && serverOk;
    };
    std::string clientKey, serverKey;
    assert(handshake(signPublic, clientKey, serverKey));
    assert(clientKey.size() == 32 && clientKey == serverKey);
    std::string secondClientKey, secondServerKey;
    assert(handshake(signPublic, secondClientKey, secondServerKey));
    assert(secondClientKey != clientKey);  // fresh keys every connection
    std::string ignoredClient, ignoredServer;
    assert(!handshake(otherPublic, ignoredClient, ignoredServer));

    std::cout << "security tests passed\n";
}

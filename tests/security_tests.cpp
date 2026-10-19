#include "../common/crypto.hpp"
#include "../common/encoding.hpp"
#include "../common/secure_channel.hpp"

#include <cassert>
#include <iostream>
#include <sys/socket.h>
#include <thread>

int main() {
    // Known answers.
    assert(crypto::sha1Hex("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert(crypto::sha1Hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d");
    crypto::Sha1 streamed;
    streamed.update("a", 1);
    streamed.update("bc", 2);
    assert(streamed.hexDigest() == "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert(toHex(crypto::sha256("abc")) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert(toHex(crypto::pbkdf2Sha256("password", "salt", 1, 32)) ==
           "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    // AES-256-GCM: any change to key, nonce, tag, ciphertext or AAD fails.
    std::string key = crypto::randomBytes(32);
    assert(key.size() == 32);
    crypto::AesGcmMessage message;
    assert(crypto::encrypt(key, "21|group|file", "GET\n3", message));
    assert(message.nonce.size() == 12 && message.tag.size() == 16);
    std::string recovered;
    assert(crypto::decrypt(key, "21|group|file", message, recovered) && recovered == "GET\n3");
    for (std::string crypto::AesGcmMessage::*field :
         {&crypto::AesGcmMessage::nonce, &crypto::AesGcmMessage::tag,
          &crypto::AesGcmMessage::ciphertext}) {
        crypto::AesGcmMessage tampered = message;
        (tampered.*field)[0] ^= 1;
        assert(!crypto::decrypt(key, "21|group|file", tampered, recovered));
    }
    assert(!crypto::decrypt(key, "21|other|file", message, recovered));
    std::string wrongKey = key;
    wrongKey[0] ^= 1;
    assert(!crypto::decrypt(wrongKey, "21|group|file", message, recovered));
    crypto::AesGcmMessage empty;
    assert(crypto::encrypt(key, "header", "", empty));
    assert(crypto::decrypt(key, "header", empty, recovered) && recovered.empty());

    // Ed25519: a signature verifies only for the same key and message.
    std::optional<crypto::KeyPair> signer = crypto::ed25519KeyPair();
    std::optional<crypto::KeyPair> other = crypto::ed25519KeyPair();
    assert(signer && other);
    std::string signature = crypto::ed25519Sign(signer->privateKey, "transcript");
    assert(signature.size() == 64);
    assert(crypto::ed25519Verify(signer->publicKey, "transcript", signature));
    assert(!crypto::ed25519Verify(signer->publicKey, "transcripT", signature));
    assert(!crypto::ed25519Verify(other->publicKey, "transcript", signature));
    std::string badSignature = signature;
    badSignature[0] ^= 1;
    assert(!crypto::ed25519Verify(signer->publicKey, "transcript", badSignature));

    // X25519: both sides derive the same secret.
    std::optional<crypto::KeyPair> a = crypto::x25519KeyPair(), b = crypto::x25519KeyPair();
    assert(a && b);
    std::string shared = crypto::x25519SharedSecret(a->privateKey, b->publicKey);
    assert(shared.size() == 32 && shared == crypto::x25519SharedSecret(b->privateKey, a->publicKey));

    // Tracker handshake over a socket pair: messages flow both ways with the
    // right pinned key; a wrong pinned key fails.
    auto handshake = [&](const std::string &pinned, std::string &sealed) {
        int fds[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        std::string received;
        std::thread server([&] {
            auto channel = SecureChannel::accept(Socket(fds[1]), signer->privateKey);
            if (channel && channel->receive(received)) channel->send("pong");
        });
        auto channel = SecureChannel::connect(Socket(fds[0]), pinned);
        std::string reply;
        bool ok = false;
        if (channel) {
            sealed = channel->seal("ping");
            ok = channel->send("ping") && channel->receive(reply) && reply == "pong";
        }
        channel.reset();
        server.join();
        return ok && received == "ping";
    };
    std::string first, second, ignored;
    assert(handshake(signer->publicKey, first));
    assert(handshake(signer->publicKey, second));
    assert(first != second);   // fresh keys every connection
    assert(!handshake(other->publicKey, ignored));

    std::cout << "security tests passed\n";
}

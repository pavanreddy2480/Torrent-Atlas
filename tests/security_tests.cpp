#include "../common/peer_crypto.hpp"
#include "../common/protocol.hpp"
#include "../common/secure_crypto.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <unistd.h>

int main() {
    assert(hexEncode(sha256("abc")) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    std::string hmacKey(20, static_cast<char>(0x0b));
    assert(hexEncode(hmacSha256(hmacKey, "Hi There")) ==
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert(hexEncode(pbkdf2HmacSha256("password", "salt", 1, 32)) ==
           "120fb6cffcf8b32c43e7225256c4f837"
           "a86548c92ccc35480805987cb70be17b");
    assert(isHexInteger("abc", 1, 3));
    assert(!isHexInteger("abz", 1, 3));

    std::string key, iv, plain, expected;
    assert(hexDecode("603deb1015ca71be2b73aef0857d7781"
                     "1f352c073b6108d72d9810a30914dff4", key));
    assert(hexDecode("000102030405060708090a0b0c0d0e0f", iv));
    assert(hexDecode("6bc1bee22e409f96e93d7e117393172a", plain));
    assert(hexDecode("f58c4c04d6e5f1ba779eabfb5f7bfbd6", expected));
    std::string encrypted = aes256CbcEncrypt(key, iv, plain);
    assert(encrypted.substr(0, 16) == expected);
    std::string decrypted;
    assert(aes256CbcDecrypt(key, iv, encrypted, decrypted));
    assert(decrypted == plain);

    std::string identityDirectory =
        "/tmp/torrent-security-identities-" + std::to_string(getpid());
    std::filesystem::remove_all(identityDirectory);
    assert(setenv("TORRENT_IDENTITY_DIR", identityDirectory.c_str(), 1) == 0);

    std::unique_ptr<PeerIdentity> firstParty =
        PeerIdentity::loadOrCreate("first");
    std::unique_ptr<PeerIdentity> secondParty =
        PeerIdentity::loadOrCreate("second");
    assert(firstParty);
    assert(secondParty);
    assert(firstParty->publicHex().size() == 64);

    std::string signature = firstParty->signHex("signed transcript");
    assert(firstParty->verifyHex(
        "signed transcript", signature, firstParty->publicHex()));
    assert(!firstParty->verifyHex(
        "tampered transcript", signature, firstParty->publicHex()));
    assert(!secondParty->verifyHex(
        "signed transcript", signature, secondParty->publicHex()));

    std::string firstPrivate, firstPublic, secondPrivate, secondPublic;
    std::string firstSecret, secondSecret;
    assert(firstParty->generateEphemeral(firstPrivate, firstPublic));
    assert(secondParty->generateEphemeral(secondPrivate, secondPublic));
    assert(firstParty->deriveEphemeralSecret(
        firstPrivate, secondPublic, firstSecret));
    assert(secondParty->deriveEphemeralSecret(
        secondPrivate, firstPublic, secondSecret));
    assert(firstSecret == secondSecret);

    std::string firstSession =
        firstParty->deriveSessionKey(firstSecret, "handshake transcript");
    std::string secondSession =
        secondParty->deriveSessionKey(secondSecret, "handshake transcript");
    assert(firstSession == secondSession);
    assert(firstSession.size() == 32);

    PeerAeadMessage message;
    assert(firstParty->encrypt(
        firstSession, "authenticated header", "piece bytes", message));
    std::string recovered;
    assert(secondParty->decrypt(
        secondSession, "authenticated header", message, recovered));
    assert(recovered == "piece bytes");
    message.tag[0] ^= 1;
    assert(!secondParty->decrypt(
        secondSession, "authenticated header", message, recovered));

    std::string persistedPublicKey = firstParty->publicHex();
    firstParty.reset();
    firstParty = PeerIdentity::loadOrCreate("first");
    assert(firstParty);
    assert(firstParty->publicHex() == persistedPublicKey);
    std::filesystem::remove_all(identityDirectory);

    std::cout << "security tests passed\n";
}

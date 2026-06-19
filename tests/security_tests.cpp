#include "../common/elgamal.hpp"
#include "../common/protocol.hpp"

#include <cassert>
#include <iostream>

int main() {
    assert(hexEncode(sha256("abc")) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    std::string hmacKey(20, static_cast<char>(0x0b));
    assert(hexEncode(hmacSha256(hmacKey, "Hi There")) ==
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

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

    ElGamalKey receiver;
    std::string session = randomBytes(32), recovered;
    ElGamalCipher cipher = receiver.encrypt(session, receiver.publicHex());
    assert(receiver.decrypt(cipher, recovered, 32));
    assert(recovered == session);
    std::string digest = sha256("signed transcript");
    ElGamalSignature signature = receiver.sign(digest);
    assert(receiver.verify(digest, signature, receiver.publicHex()));
    assert(!receiver.verify(sha256("tampered transcript"), signature, receiver.publicHex()));

    std::cout << "security tests passed\n";
}

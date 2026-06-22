#include "../common/protocol.hpp"
#include "../common/secure_crypto.hpp"

#include <cassert>
#include <iostream>

int main() {
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

    std::cout << "security tests passed\n";
}

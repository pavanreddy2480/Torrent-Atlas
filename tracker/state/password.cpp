#include "tracker/state/password.hpp"

#include "common/crypto/crypto.hpp"
#include "common/encoding.hpp"

namespace password {

namespace {
constexpr unsigned ITERATIONS = 20000;
constexpr std::size_t DIGEST_SIZE = 32;
}  // namespace

std::string hash(const std::string &password, const std::string &salt) {
    if (salt.size() != 16) return {};
    std::string digest = crypto::pbkdf2Sha256(password, salt, ITERATIONS, DIGEST_SIZE);
    if (digest.empty()) return {};
    return "pbkdf2-sha256$" + std::to_string(ITERATIONS) + "$" + toHex(salt) + "$" + toHex(digest);
}

bool verify(const std::string &password, const std::string &stored) {
    std::vector<std::string> fields = split(stored, '$');
    u64 iterations = 0;
    std::string salt, expected;
    if (fields.size() != 4 || fields[0] != "pbkdf2-sha256" || !parseU64(fields[1], iterations) ||
        iterations == 0 || iterations > 1000000 || !fromHex(fields[2], salt) ||
        !fromHex(fields[3], expected) || salt.size() != 16 || expected.size() != DIGEST_SIZE)
        return false;
    std::string actual =
        crypto::pbkdf2Sha256(password, salt, static_cast<unsigned>(iterations), DIGEST_SIZE);
    bool valid = crypto::constantTimeEqual(actual, expected);
    crypto::secureErase(actual);
    return valid;
}

}  // namespace password

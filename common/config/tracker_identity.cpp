#include "common/config/tracker_identity.hpp"

#include "common/config/client_config.hpp"
#include "common/crypto/crypto.hpp"
#include "common/encoding.hpp"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace {

std::string keyPath(const std::string &keysDir) { return keysDir + "/tracker_identity.key"; }

}  // namespace

bool TrackerIdentity::create(const Endpoint &tracker, const std::string &keysDir,
                             const std::string &clientConfPath, std::string &error) {
    std::error_code ignored;
    fs::create_directories(keysDir, ignored);
    fs::permissions(keysDir, fs::perms::owner_all, fs::perm_options::replace, ignored);

    std::optional<crypto::KeyPair> identity = crypto::ed25519KeyPair();
    if (!identity) {
        error = "could not generate the tracker identity key";
        return false;
    }
    {
        std::ofstream output(keyPath(keysDir), std::ios::trunc);
        if (!(output << toHex(identity->privateKey) << '\n')) {
            error = "could not write " + keyPath(keysDir);
            return false;
        }
    }
    fs::permissions(keyPath(keysDir), fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ignored);
    crypto::secureErase(identity->privateKey);
    if (!ClientConfig{tracker, identity->publicKey}.save(clientConfPath)) {
        error = "could not write " + clientConfPath;
        return false;
    }
    return true;
}

std::optional<TrackerIdentity> TrackerIdentity::load(const std::string &keysDir) {
    std::ifstream input(keyPath(keysDir));
    std::string hex, extra;
    TrackerIdentity identity;
    if (!(input >> hex) || (input >> extra) || !fromHex(hex, identity.privateKey_) ||
        identity.privateKey_.size() != 32)
        return std::nullopt;
    return identity;
}

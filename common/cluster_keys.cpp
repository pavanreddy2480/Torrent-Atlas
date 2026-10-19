#include "cluster_keys.hpp"

#include "client_config.hpp"
#include "crypto.hpp"
#include "encoding.hpp"
#include "openssl_ptr.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace {

using Key = OpenSslPtr<EVP_PKEY, EVP_PKEY_free>;
using Cert = OpenSslPtr<X509, X509_free>;

const std::string IDENTITY_KEY_FILE = "tracker_identity.key";

std::string nodeBase(const std::string &keysDir, int id) {
    return keysDir + "/node" + std::to_string(id);
}

void restrictToOwner(const std::string &path) {
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace);
}

// A certificate for subjectKey, signed by the issuer (self-signed when
// issuerCert is null).
Cert makeCert(EVP_PKEY *subjectKey, const std::string &commonName, X509 *issuerCert,
              EVP_PKEY *issuerKey, long serial, bool ca) {
    Cert cert(X509_new());
    if (!cert) return nullptr;
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 10L * 365 * 24 * 3600);
    X509_set_pubkey(cert.get(), subjectKey);
    X509_NAME *name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(commonName.c_str()), -1,
                               -1, 0);
    X509_set_issuer_name(cert.get(), issuerCert ? X509_get_subject_name(issuerCert) : name);
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuerCert ? issuerCert : cert.get(), cert.get(), nullptr, nullptr, 0);
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(
        nullptr, &context, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    if (extension) {
        X509_add_ext(cert.get(), extension, -1);
        X509_EXTENSION_free(extension);
    }
    if (X509_sign(cert.get(), issuerKey, EVP_sha256()) <= 0) return nullptr;
    return cert;
}

bool writeCert(const std::string &path, X509 *cert) {
    FILE *file = std::fopen(path.c_str(), "w");
    if (!file) return false;
    bool ok = PEM_write_X509(file, cert) == 1;
    std::fclose(file);
    return ok;
}

bool writePrivateKey(const std::string &path, EVP_PKEY *key) {
    FILE *file = std::fopen(path.c_str(), "w");
    if (!file) return false;
    bool ok = PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    std::fclose(file);
    if (ok) restrictToOwner(path);
    return ok;
}

// Writes a key pair for one subject: <base>.crt and <base>.key.
bool writeCertAndKey(const std::string &base, const std::string &commonName, X509 *issuerCert,
                     EVP_PKEY *issuerKey, long serial, Key &key, Cert &cert) {
    key = Key(EVP_EC_gen("P-256"));
    if (!key) return false;
    bool selfSigned = issuerCert == nullptr;
    cert = makeCert(key.get(), commonName, issuerCert, selfSigned ? key.get() : issuerKey,
                    serial, selfSigned);
    return cert && writeCert(base + ".crt", cert.get()) && writePrivateKey(base + ".key", key.get());
}

bool writeIdentityKey(const std::string &path, const std::string &privateKey) {
    {
        std::ofstream output(path, std::ios::trunc);
        if (!(output << toHex(privateKey) << '\n')) return false;
    }
    restrictToOwner(path);
    return true;
}

}  // namespace

bool generateClusterKeys(const ClusterConfig &cluster, const std::string &keysDir,
                         const std::string &clientConfPath, std::string &error) {
    std::error_code ignored;
    fs::create_directories(keysDir, ignored);
    fs::permissions(keysDir, fs::perms::owner_all, fs::perm_options::replace, ignored);

    Key caKey;
    Cert caCert;
    if (!writeCertAndKey(keysDir + "/ca", "torrent-cluster-ca", nullptr, nullptr, 1, caKey, caCert)) {
        error = "could not create the cluster CA in " + keysDir;
        return false;
    }
    for (const ClusterMember &member : cluster.members()) {
        Key key;
        Cert cert;
        if (!writeCertAndKey(nodeBase(keysDir, member.id),
                             "torrent-node-" + std::to_string(member.id), caCert.get(),
                             caKey.get(), 100 + member.id, key, cert)) {
            error = "could not create the certificate for node " + std::to_string(member.id);
            return false;
        }
    }
    std::optional<crypto::KeyPair> identity = crypto::ed25519KeyPair();
    ClientConfig clientConfig;
    for (const ClusterMember &member : cluster.members())
        clientConfig.trackers.push_back(member.client);
    if (identity) clientConfig.trackerPublicKey = identity->publicKey;
    if (!identity || !writeIdentityKey(keysDir + "/" + IDENTITY_KEY_FILE, identity->privateKey) ||
        !clientConfig.save(clientConfPath)) {
        error = "could not write the tracker identity key or " + clientConfPath;
        return false;
    }
    return true;
}

std::optional<NodeKeys> NodeKeys::load(const std::string &keysDir, int nodeId) {
    NodeKeys keys;
    keys.caCertFile = keysDir + "/ca.crt";
    keys.certFile = nodeBase(keysDir, nodeId) + ".crt";
    keys.keyFile = nodeBase(keysDir, nodeId) + ".key";
    std::ifstream input(keysDir + "/" + IDENTITY_KEY_FILE);
    std::string hex, extra;
    if (!fs::exists(keys.caCertFile) || !fs::exists(keys.certFile) || !fs::exists(keys.keyFile) ||
        !(input >> hex) || (input >> extra) || !fromHex(hex, keys.identityKey) ||
        keys.identityKey.size() != 32)
        return std::nullopt;
    return keys;
}

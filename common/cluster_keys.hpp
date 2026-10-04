#pragma once

// Creates every key a deployment needs from cluster.conf:
//   <keys>/ca.crt, ca.key          cluster certificate authority (P-256)
//   <keys>/node<id>.crt, .key      each tracker's TLS certificate, CN=torrent-node-<id>
//   <keys>/tracker_identity.key    Ed25519 key the trackers sign client handshakes with
//   <client.conf>                  every tracker's client address, then the
//                                  Ed25519 public key clients pin
// Private keys are written with mode 0600.

#include "cluster_config.hpp"
#include "secure_channel.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <memory>
#include <sys/stat.h>

namespace cluster_keys_detail {

struct PkeyFree { void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); } };
struct X509Free { void operator()(X509 *cert) const { X509_free(cert); } };
using Key = std::unique_ptr<EVP_PKEY, PkeyFree>;
using Cert = std::unique_ptr<X509, X509Free>;

inline Key newEcKey() { return Key(EVP_EC_gen("P-256")); }

inline Cert makeCert(EVP_PKEY *subjectKey, const std::string &commonName,
                     X509 *issuerCert, EVP_PKEY *issuerKey, long serial, bool ca) {
    Cert cert(X509_new());
    if (!cert) return nullptr;
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 10L * 365 * 24 * 3600);
    X509_set_pubkey(cert.get(), subjectKey);
    X509_NAME *name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(commonName.c_str()),
                               -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuerCert ? X509_get_subject_name(issuerCert) : name);
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuerCert ? issuerCert : cert.get(), cert.get(), nullptr,
                   nullptr, 0);
    const char *constraints = ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
    X509_EXTENSION *extension =
        X509V3_EXT_conf_nid(nullptr, &context, NID_basic_constraints, constraints);
    if (extension) {
        X509_add_ext(cert.get(), extension, -1);
        X509_EXTENSION_free(extension);
    }
    if (X509_sign(cert.get(), issuerKey, EVP_sha256()) <= 0) return nullptr;
    return cert;
}

inline bool writePem(const std::string &path, X509 *cert, EVP_PKEY *key) {
    FILE *file = std::fopen(path.c_str(), "w");
    if (!file) return false;
    bool ok = cert ? PEM_write_X509(file, cert) == 1
                   : PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    std::fclose(file);
    return ok && (cert || chmod(path.c_str(), 0600) == 0);
}

}  // namespace cluster_keys_detail

inline bool writeClientConfig(const std::string &path, const std::vector<ClusterMember> &members,
                              const std::string &identityPublicKey) {
    std::ofstream output(path, std::ios::trunc);
    for (const auto &member : members) output << endpointKey(member.client) << '\n';
    output << hexEncode(identityPublicKey) << '\n';
    return static_cast<bool>(output);
}

inline bool generateClusterKeys(const std::vector<ClusterMember> &members,
                                const std::string &keysDir, const std::string &clientConf,
                                std::string &error) {
    using namespace cluster_keys_detail;
    ::mkdir(keysDir.c_str(), 0700);
    Key caKey = newEcKey();
    Cert caCert = caKey ? makeCert(caKey.get(), "torrent-cluster-ca", nullptr, caKey.get(), 1, true)
                        : nullptr;
    if (!caCert || !writePem(keysDir + "/ca.crt", caCert.get(), nullptr) ||
        !writePem(keysDir + "/ca.key", nullptr, caKey.get())) {
        error = "could not create the cluster CA in " + keysDir;
        return false;
    }
    for (const auto &member : members) {
        std::string base = keysDir + "/node" + std::to_string(member.id);
        Key key = newEcKey();
        Cert cert = key ? makeCert(key.get(), "torrent-node-" + std::to_string(member.id),
                                   caCert.get(), caKey.get(), 100 + member.id, false)
                        : nullptr;
        if (!cert || !writePem(base + ".crt", cert.get(), nullptr) ||
            !writePem(base + ".key", nullptr, key.get())) {
            error = "could not create the certificate for node " + std::to_string(member.id);
            return false;
        }
    }
    std::string identityPrivate, identityPublic;
    if (!ed25519KeyPair(identityPrivate, identityPublic) ||
        !writeKeyFile(keysDir + "/tracker_identity.key", identityPrivate, true) ||
        !writeClientConfig(clientConf, members, identityPublic)) {
        error = "could not write the tracker identity key or " + clientConf;
        return false;
    }
    return true;
}

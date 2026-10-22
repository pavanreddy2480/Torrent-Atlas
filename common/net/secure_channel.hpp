#pragma once

/// @file secure_channel.hpp
/// The encrypted, authenticated client <-> tracker channel, on top of
/// Socket frames. See SECURITY.md section 4 for the full picture.
///
/// Handshake (one round trip per connection):
///   client  -> "HELLO|<X25519 public>|<nonce>|<time>"
///   tracker -> "HELLO|<X25519 public>|<nonce>|<time>|<Ed25519 signature>"
/// The tracker signs the transcript (both hellos) with its identity key,
/// which the client already knows from client.conf, so a client can't be
/// fooled by an impostor. Both sides then compute
///   session key = SHA-256(X25519 shared secret || transcript)
/// and every later frame is AES-256-GCM under that key, labelled by
/// direction. Fresh keys on both sides make a recorded connection useless
/// to replay, and erasing them after use gives forward secrecy.

#include "common/net/net.hpp"

#include <optional>
#include <string>

/// One established secure connection. Move-only; erases its session key on
/// destruction. Not thread-safe.
class SecureChannel {
public:
    /// Client side of the handshake.
    /// @param socket           A connected socket; the channel takes it over.
    /// @param trackerPublicKey The pinned 32-byte Ed25519 key from client.conf.
    /// @return The channel, or std::nullopt if the tracker's signature does
    ///         not verify, its hello is malformed or stale, or I/O fails.
    static std::optional<SecureChannel> connect(Socket socket, const std::string &trackerPublicKey);

    /// Tracker side of the handshake.
    /// @param socket             A freshly accepted socket; taken over.
    /// @param identityPrivateKey The tracker's raw 32-byte Ed25519 key.
    /// @return The channel, or std::nullopt if the client's hello is
    ///         malformed or stale, or I/O fails.
    static std::optional<SecureChannel> accept(Socket socket, const std::string &identityPrivateKey);

    SecureChannel(SecureChannel &&) = default;
    SecureChannel &operator=(SecureChannel &&) = default;
    /// Erases the session key.
    ~SecureChannel();

    /// Encrypts plain and sends it as one frame.
    /// @return false if encryption or the send failed.
    bool send(const std::string &plain) { return socket_.sendFrame(seal(plain)); }

    /// Receives one frame and decrypts it.
    /// @param plain Receives the plaintext.
    /// @return false on disconnect, timeout, or a frame that fails to
    ///         authenticate (tampered, replayed, or the wrong direction).
    bool receive(std::string &plain);

    /// The exact frame send() would write for plain: nonce || tag ||
    /// ciphertext. Exposed so tests can replay a sealed frame.
    /// @return The frame, or "" if encryption failed.
    std::string seal(const std::string &plain) const;

    /// The underlying socket, for tests that write raw frames.
    Socket &socket() { return socket_; }

private:
    /// @param key    The 32-byte session key from the handshake.
    /// @param client true on the client side; picks the direction labels.
    SecureChannel(Socket socket, std::string key, bool client);

    Socket socket_;
    std::string key_;            ///< Session key; erased in the destructor.
    std::string sendLabel_;      ///< AAD for frames we send.
    std::string receiveLabel_;   ///< AAD expected on frames we receive.
};

/// Sends one request to the tracker and reads its reply over a new
/// SecureChannel; the connection is closed afterwards.
/// @param tracker          Where to connect.
/// @param trackerPublicKey The pinned Ed25519 public key.
/// @param request          Plaintext request, e.g. "C\t<session>\t<command>".
/// @param response         Receives the plaintext reply.
/// @param timeoutSeconds   Connect, send and receive timeout.
/// @return false if the tracker can't be reached or authenticated, or the
///         exchange fails; response is then unspecified.
bool callTracker(const Endpoint &tracker, const std::string &trackerPublicKey,
                 const std::string &request, std::string &response, int timeoutSeconds = 5);

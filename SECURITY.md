# Secure Peer-to-Peer Protocol

## Threat model and trust assumptions

The secure piece protocol protects file contents against passive interception, detects message
modification, authenticates the seeder whose public key was returned by a tracker, rejects stale
requests and replayed nonces, and prevents clients without a group-issued file capability from
requesting pieces.

Tracker responses are the trust anchor for group authorization, capabilities, and seeder public
keys. The current tracker-client control channel is not encrypted. Deploy it on a trusted network
or add pre-provisioned tracker signing keys before using this as an Internet-facing system.

Tracker passwords are held as salted PBKDF2-HMAC-SHA256 verifiers rather than plaintext.
Session identifiers are generated from `/dev/urandom` and include a tracker-specific prefix.
Five consecutive password failures trigger a 30-second tracker-local account lockout.

## Cryptographic primitives

- OpenSSL Ed25519 signatures for persistent peer identities.
- OpenSSL X25519 for fresh per-request ephemeral key agreement.
- HKDF-SHA256 for transcript-bound session-key derivation.
- ChaCha20-Poly1305 authenticated encryption for requests, bitmaps, and pieces.
- OpenSSL SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and secure randomness.
- Existing SHA-1 hashes remain only as assignment-required file-integrity identifiers.

Run primitive vectors, signature/key-agreement tests, AEAD tamper tests, and identity
persistence tests with:

```sh
make security-test
```

## Secure piece protocol

Every client loads or creates an Ed25519 identity key. By default it is stored under
`~/.torrent-dashboard/identities`; `TORRENT_IDENTITY_DIR` overrides this location. Directories
use mode 0700 and private-key files use mode 0600. Upload metadata registers the seeder public
key and a random 256-bit file capability with the tracker. Only authenticated group members
receive that capability and the list of seeder public keys.

### Opcode 20: signed ephemeral hello

The downloader creates:

- a random 128-bit client nonce;
- a timestamp;
- a fresh X25519 private/public value;
- an Ed25519 signature over the timestamp, nonce, ephemeral public value, and client identity
  public key.

The seeder rejects timestamps outside a 60-second window, malformed signatures, and repeated
authenticated nonces.

### Opcode 25: signed ephemeral response

The seeder creates its own fresh X25519 value and nonce, derives the shared secret, and signs the
complete two-party handshake transcript. The downloader requires the signing key to exactly
match the public key returned by the tracker. Both sides derive:

```text
session = HKDF-SHA256(X25519 shared secret, SHA256(signed transcript), "torrent-peer-v2")
```

Ephemeral private values and raw shared secrets are overwritten after derivation.

### Opcode 21: encrypted request

After authenticating the handshake, the downloader encrypts the group, file, piece index, and
capability with ChaCha20-Poly1305. The signed handshake transcript is additional authenticated
data.

### Opcode 30: authenticated piece response

The seeder reads the requested piece only after authorization, encrypts it with
ChaCha20-Poly1305, and signs the response transcript with Ed25519. The downloader verifies the
signature and AEAD tag, then immediately checks the assignment-required piece SHA-1 before
writing with `pwrite`.

The same authenticated channel supports `BITMAP` requests. Bitmap responses disclose only
whether each piece has already been verified; they are encrypted, signed, and AEAD-protected
like file data. Unverified partial-file regions are never served.

## Malicious peer isolation

Each client maintains evidence per peer:

- successful authenticated transfers;
- measured bytes and elapsed transfer time;
- network failures;
- signature, AEAD, replay, and authorization failures;
- decrypted pieces whose SHA-1 does not match tracker metadata.

Scheduler preference combines trust and measured throughput. Authentication and corruption
events are weighted heavily, and three such events blacklist the endpoint for five minutes.
Timeouts reduce preference without immediate blacklisting. This distinction prevents an
overloaded honest peer from being treated like a peer supplying forged data.

The reputation state is local to each client, so a malicious client cannot submit arbitrary
negative reports to globally frame another peer.

### Opcode 60: rejection

Malformed, stale, replayed, unauthenticated, unauthorized, or undecryptable requests receive a
small opcode-60 rejection without file data.

## Freshness and replay protection

Freshness uses both a timestamp window and a random 128-bit nonce. A seeder maintains a
thread-safe cache of recently authenticated nonces. Replaying the same valid request therefore
returns opcode 60. The server nonce is included in the signed response transcript.

## Key derivation and authentication

The raw X25519 shared secret is never used directly. HKDF-SHA256 binds the session key to the
signed handshake transcript. ChaCha20-Poly1305 authenticates ciphertext and associated protocol
metadata in one operation and does not use padding.

## Forward secrecy

Piece and bitmap sessions use fresh X25519 values authenticated by long-term Ed25519 signatures.
Long-term keys sign the exchange but do not derive its encryption key.
Later compromise of a client's long-term signing key therefore does not reveal shared secrets
from previously recorded sessions.

This assumes secure randomness, uncompromised endpoints during the live exchange, and
effective destruction of ephemeral process memory. It does not protect plaintext already
stored at an endpoint or captured from a compromised process.

## Operational limitations

- Client identity private keys persist in restricted local files so tracker-advertised identities
  remain stable across restarts.
- A clean logout removes advertised shares. After a crash, re-uploading the same file replaces
  the stale endpoint while retaining the tracker capability.
- AEAD ciphertext is accepted only after ChaCha20-Poly1305 tag verification.
- The file capability is authorization material and must not be logged or disclosed.
- Resume manifests contain capabilities and verified-piece state, so they are atomically written
  with mode 0600.

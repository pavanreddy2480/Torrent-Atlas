# Secure Peer-to-Peer Protocol

## Threat model and trust assumptions

The secure piece protocol protects file contents against passive interception, detects message
modification, authenticates the seeder whose public key was returned by a tracker, rejects stale
requests and replayed nonces, and prevents clients without a group-issued file capability from
requesting pieces.

Tracker responses are the trust anchor for group authorization, capabilities, and seeder public
keys. The current tracker-client control channel is not encrypted. Deploy it on a trusted network
or add pre-provisioned tracker signing keys before using this as an Internet-facing system.

## Cryptographic primitives

- RFC 3526 2048-bit MODP group with generator 2.
- Manually implemented ElGamal encryption/decryption and signatures.
- Manually implemented square-and-multiply modular exponentiation.
- Manually implemented modular inverse using extended Euclidean arithmetic.
- GMP only supplies arbitrary-precision integer storage and basic arithmetic.
- Manually implemented SHA-256, HMAC-SHA256, and AES-256-CBC.
- `/dev/urandom` supplies private exponents, session keys, IVs, and nonces.
- Existing SHA-1 hashes remain the assignment-required file-integrity identifiers.

Run published primitive test vectors and ElGamal round trips with:

```sh
make security-test
```

## Secure piece protocol

Every client creates a 2048-bit ElGamal identity key when it starts. Upload metadata registers
the seeder public key and a random 256-bit file capability with the tracker. Only authenticated
group members receive that capability and the list of seeder public keys.

### Opcode 20: signed ephemeral hello

The downloader creates:

- a random 128-bit client nonce;
- a timestamp;
- a fresh private/public Diffie-Hellman value in the 2048-bit group;
- an ElGamal signature over the timestamp, nonce, ephemeral public value, and client identity
  public key.

The seeder rejects timestamps outside a 60-second window, malformed signatures, and repeated
authenticated nonces.

### Opcode 25: signed ephemeral response

The seeder creates its own fresh DH value and nonce, derives the shared secret, and signs the
complete two-party handshake transcript. The downloader requires the signing key to exactly
match the public key returned by the tracker. Both sides derive:

```text
session = SHA256(DH shared secret || signed transcript)
```

Ephemeral private values and raw shared secrets are overwritten after derivation.

### Opcode 21: encrypted request

After authenticating the handshake, the downloader encrypts the group, file, piece index, and
capability using the ephemeral session and authenticates the ciphertext with HMAC-SHA256.

### Opcode 30: authenticated piece response

The seeder:

- reads the requested piece only after authorization;
- encrypts it with AES-256-CBC under keys derived from the request session key;
- signs the client nonce, fresh server nonce, and encrypted-piece digest with ElGamal;
- computes HMAC-SHA256 over the complete response.

The downloader verifies HMAC and signature before decryption, then immediately checks the
assignment-required piece SHA-1 before writing with `pwrite`.

The same authenticated channel supports `BITMAP` requests. Bitmap responses disclose only
whether each piece has already been verified; they are encrypted, signed, and MAC-protected
like file data. Unverified partial-file regions are never served.

## Malicious peer isolation

Each client maintains evidence per peer:

- successful authenticated transfers;
- measured bytes and elapsed transfer time;
- network failures;
- signature, HMAC, replay, and authorization failures;
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

## Key separation

The ephemeral session secret is not used directly. SHA-256 derives independent labels:

```text
encryption key = SHA256(session key || "ENC")
MAC key        = SHA256(session key || "MAC")
```

The protocol uses encrypt-then-MAC. Padding is checked only after the HMAC succeeds.

## Forward secrecy

Piece and bitmap sessions use fresh ephemeral Diffie-Hellman values authenticated by long-term
ElGamal signatures. Long-term keys sign the exchange but do not derive its encryption key.
Later compromise of a client's long-term signing key therefore does not reveal shared secrets
from previously recorded sessions.

This assumes secure randomness, uncompromised endpoints during the live exchange, and
effective destruction of ephemeral process memory. It does not protect plaintext already
stored at an endpoint or captured from a compromised process.

## Operational limitations

- Client identity private keys are process-lifetime keys and are not written to disk.
- A clean logout removes advertised shares. After a crash, re-uploading the same file replaces
  the stale endpoint while retaining the tracker capability.
- AES-CBC is always paired with HMAC-SHA256; CBC ciphertext must never be accepted without
  successful MAC verification.
- The file capability is authorization material and must not be logged or disclosed.
- Resume manifests contain capabilities and verified-piece state, so they are atomically written
  with mode 0600.

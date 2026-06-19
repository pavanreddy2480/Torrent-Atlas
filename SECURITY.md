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

### Opcode 20: authenticated request

The downloader creates:

- a random 256-bit request session key;
- a random 128-bit client nonce;
- a timestamp;
- an ElGamal encryption of the session key for the selected seeder;
- an AES-256-CBC encryption of group, file, piece index, and capability;
- an HMAC-SHA256 over the complete request header and ciphertext.

The seeder rejects timestamps outside a 60-second window, malformed values, invalid HMACs,
invalid capabilities, and repeated authenticated nonces.

### Opcode 30: authenticated piece response

The seeder:

- reads the requested piece only after authorization;
- encrypts it with AES-256-CBC under keys derived from the request session key;
- signs the client nonce, fresh server nonce, and encrypted-piece digest with ElGamal;
- computes HMAC-SHA256 over the complete response.

The downloader verifies HMAC and signature before decryption, then immediately checks the
assignment-required piece SHA-1 before writing with `pwrite`.

### Opcode 60: rejection

Malformed, stale, replayed, unauthenticated, unauthorized, or undecryptable requests receive a
small opcode-60 rejection without file data.

## Freshness and replay protection

Freshness uses both a timestamp window and a random 128-bit nonce. A seeder maintains a
thread-safe cache of recently authenticated nonces. Replaying the same valid request therefore
returns opcode 60. The server nonce is included in the signed response transcript.

## Key separation

The random request secret is not used directly. SHA-256 derives independent labels:

```text
encryption key = SHA256(session key || "ENC")
MAC key        = SHA256(session key || "MAC")
```

The protocol uses encrypt-then-MAC. Padding is checked only after the HMAC succeeds.

## Forward secrecy

This implementation does **not** claim true forward secrecy. Like the protocol in
`security.pdf`, it encrypts a session secret under a long-term ElGamal public key. Compromise of
the seeder private key plus recorded traffic can recover historical request session keys.

True forward secrecy requires an ephemeral authenticated Diffie-Hellman exchange and secure
erasure of ephemeral private values. That extension is intentionally not claimed here.

## Operational limitations

- Client identity private keys are process-lifetime keys and are not written to disk.
- A clean logout removes advertised shares. After a crash, re-uploading the same file replaces
  the stale endpoint while retaining the tracker capability.
- AES-CBC is always paired with HMAC-SHA256; CBC ciphertext must never be accepted without
  successful MAC verification.
- The file capability is authorization material and must not be logged or disclosed.

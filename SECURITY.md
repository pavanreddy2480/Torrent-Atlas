# Simple Peer Security

## Security model

The tracker gives each authorized group member:

- the seeder's network address;
- a random 256-bit capability for the requested file.

That capability is the shared AES-256 key. Tracker connections therefore must run on a trusted
network because tracker traffic currently is not encrypted.

## Peer protocol

There is no separate security handshake.

### Opcode 21: encrypted request

The downloader sends the group and file name as authenticated metadata. The operation (`GET` or
`BITMAP`) and piece index are encrypted with AES-256-GCM using the file capability.

AES-GCM creates a fresh 96-bit nonce for every message and produces a 128-bit authentication tag.
The seeder serves data only when decryption and tag verification succeed.

### Opcode 30: encrypted response

The seeder encrypts the bitmap or piece with the same capability. The response is authenticated
against the original request metadata and request nonce so it cannot be substituted for another
request.

### Opcode 60: rejection

Malformed messages, unknown files, invalid tags, unavailable pieces, and unauthorized requests
receive a small error response without file data.

## Other protections

- OpenSSL `RAND_bytes` generates capabilities, AES nonces, password salts, and tracker sessions.
- Tracker passwords are stored as PBKDF2-HMAC-SHA256 verifiers with random salts.
- Password-verifier comparisons use constant-time comparison.
- Five failed logins temporarily lock the account.
- SHA-1 remains only for assignment-required piece and full-file integrity verification.
- Resume manifests containing capabilities are written with mode `0600`.

## Tradeoffs

Anyone who receives a file capability can act as a downloader or seeder for that file. The design
does not provide peer identity authentication or forward secrecy. It intentionally prioritizes a
small protocol that is easy to explain: the tracker distributes a secret file key, and peers use
AES-GCM with that key to encrypt and authenticate requests and responses.

Run the security tests with:

```sh
make security-test
```

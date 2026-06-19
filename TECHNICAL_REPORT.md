# Technical Report

## Implementation approach

The system separates metadata coordination from data transfer. Two tracker processes maintain
user, group, file, hash, and seeder information. Clients use trackers for authorization and peer
discovery, then transfer pieces directly between client peer servers.

The implementation uses C++17 standard containers and POSIX calls: TCP sockets, `open`,
`read`, `pread`, `pwrite`, `ftruncate`, `rename`, and threads. It does not use database,
filesystem, process-execution, or external torrent libraries. GMP is used only for arbitrary
precision storage/arithmetic required by the manual 2048-bit ElGamal implementation.

## Synchronization algorithm

Every successful mutation is first applied under one tracker-state mutex. The resulting state is
atomically persisted through a temporary file and `rename`. The original command and session
token are then added to a persistent FIFO queue. A dedicated synchronization thread repeatedly
connects to the peer tracker and removes an item only after acknowledgement.

Commands are designed to be idempotent when replayed. This matters when acknowledgement is
lost after the peer already applied an update. If a tracker starts without local state, it requests
a full snapshot from the other tracker. Persistent state plus persistent pending operations covers
temporary disconnection and process restart without requiring both trackers to remain online.

This is primary-primary asynchronous replication, not consensus. It preserves ordered normal
updates but cannot automatically resolve contradictory writes independently accepted on both
sides of a partition.

## Piece selection and download algorithm

Files are split into 512 KiB pieces, with a shorter final piece. Upload computes ordered piece
SHA1 values and a complete-file SHA1 using a streaming implementation.

For a download, the client first requests encrypted piece bitmaps from all candidate peers. It
computes the replication count of each piece and sorts pieces in ascending availability order.
A bounded worker pool therefore fetches rare pieces before common pieces. Equal-quality peers
are striped initially; later selections prefer peers with stronger reputation and throughput.

The last three pieces use endgame mode. Two peers receive the same request concurrently and
the first authenticated, SHA1-valid response wins. Losing requests do not write to the output,
so the downloader can finish without waiting for a slow duplicate.

After every successful `pwrite`, the local verified bitmap changes from zero to one. The partial
file is already registered with the tracker, allowing other clients to discover and securely
request those pieces while the original download remains in progress.

The same bitmap is written to a crash-safe resume manifest only after `fsync` makes the piece
durable. Manifests bind group, file name, size, complete hash, capability, ordered piece hashes,
temporary path, and verified bitmap. Restart recovery re-hashes every marked piece before
trusting it. Invalid bits are cleared and scheduled normally.

Verified pieces are written at fixed offsets with `pwrite`, allowing workers to share one output
descriptor safely. The output is a unique temporary file. After all workers finish, the complete
file is hashed and atomically renamed only on success.

## Protocol rationale

Length-prefixed framing avoids dependence on TCP packet boundaries and supports binary piece
payloads. A 32-bit network-order size bounds allocation. Tracker payloads are textual for easy
inspection; file names are hex encoded to protect field boundaries. Peer responses put a
one-byte success/error marker before binary data.

The protocol deliberately opens short-lived connections. This simplifies failure isolation and
avoids shared connection synchronization while still supporting concurrent transfers.

Peer requests extend the security model in `security.pdf` with forward secrecy. Both peers
generate fresh 2048-bit Diffie-Hellman values and sign the complete exchange using long-term
ElGamal identity keys. The session is derived from the ephemeral shared secret and transcript;
long-term keys never derive the content-encryption key. Request/response nonces provide
freshness, AES-256-CBC protects content, and HMAC-SHA256 authenticates ciphertext before
decryption. Manual implementations and exact primitive test vectors are in
`common/secure_crypto.hpp`, `common/elgamal.hpp`, and `tests/security_tests.cpp`.

## Concurrency and resource control

Tracker maps are protected by one mutex to make multi-object operations atomic. Synchronization
queues have a separate mutex and condition variable. Client sharing metadata and download
history have separate mutexes. Piece indices and progress counters are atomic.

Each file download uses at most eight workers, limiting descriptors and memory. Each worker
holds at most one roughly 512 KiB response. Hashing uses one 512 KiB buffer regardless of file
size.

## Challenges and solutions

- TCP partial transmission: exact-length read/write loops.
- Corrupt data: verify each response before disk write, then verify the whole temporary file.
- Tracker outage: endpoint failover and persistent queued replication.
- Tracker restart: atomic state snapshots and peer snapshot recovery.
- Concurrent output writes: disjoint `pwrite` offsets.
- Incomplete destination exposure: temporary files and atomic rename.
- Lost replication acknowledgement: idempotent replay behavior.
- Malicious seeders: local evidence-based scoring, heavy integrity penalties, and timed
  blacklisting.
- Slow final pieces: duplicate endgame requests with first-valid-response selection.
- Client crashes: durable per-piece manifests, restart-time SHA1 revalidation, and automatic
  continuation from the missing-piece set.
- Long-term key compromise: signed ephemeral Diffie-Hellman provides forward secrecy for past
  piece-transfer sessions.

## External resources

The implementation follows the SHA-1 algorithm structure defined by FIPS PUB 180-4. No
external source code or torrent implementation is included.

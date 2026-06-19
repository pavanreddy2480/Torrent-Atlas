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

For a download, an atomic counter assigns every piece exactly once to a bounded worker pool.
The starting peer is rotated by piece and worker index to spread load. On connection failure,
truncated transfer, or hash mismatch, the worker discards the response and tries other peers.
Temporary network failures receive bounded retry rounds.

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

Peer requests follow the security model in `security.pdf`: a fresh 256-bit secret is ElGamal
encrypted to the seeder, request/response nonces provide freshness, the seeder signs the
response transcript, AES-256-CBC protects content, and HMAC-SHA256 authenticates ciphertext
before decryption. Manual implementations and exact primitive test vectors are in
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

## External resources

The implementation follows the SHA-1 algorithm structure defined by FIPS PUB 180-4. No
external source code or torrent implementation is included.

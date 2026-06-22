# Technical Report

## Implementation approach

The system separates metadata coordination from data transfer. Two tracker processes maintain
user, group, file, hash, and seeder information. Clients use trackers for authorization and peer
discovery, then transfer pieces directly between client peer servers.

The implementation uses C++17 standard containers and POSIX calls: TCP sockets, `open`,
`read`, `pread`, `pwrite`, `ftruncate`, `rename`, and threads. It does not use database,
filesystem, process-execution, or external torrent libraries. OpenSSL supplies the standard
cryptographic primitives used by tracker authentication and peer transfers.

Command tokenization is isolated in a reusable parser supporting quoted and escaped paths.
Tracker passwords are represented as salted PBKDF2-HMAC-SHA256 verifiers, and tracker session
tokens use operating-system cryptographic randomness. Repeated login failures trigger a
temporary tracker-local lockout, and sensitive client command buffers are overwritten where
their lifetime is under application control.

## Synchronization algorithm

Every successful mutation is first applied under one tracker-state mutex. The resulting state is
added with its session token to an in-memory FIFO queue. A dedicated synchronization thread
repeatedly connects to the peer tracker and removes an item only after acknowledgement.

Commands are designed to be idempotent when replayed. This matters when acknowledgement is
lost after the peer already applied an update. A restarting tracker requests a full in-memory
snapshot from a peer that is still running. No tracker metadata or pending replication is written
to disk, so stopping both trackers deliberately starts the next deployment with empty state.

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

Peer security uses the tracker-issued 256-bit file capability directly as an AES-256-GCM key.
There is no separate handshake. AES-GCM encrypts each request and response and rejects modified
messages. Group and file identifiers are authenticated metadata, while operations, piece indexes,
bitmaps, and piece data are encrypted. The implementation and primitive tests are in
`common/secure_crypto.hpp` and `tests/security_tests.cpp`.

## Concurrency and resource control

Tracker maps are protected by one mutex to make multi-object operations atomic. Synchronization
queues have a separate mutex and condition variable. Client sharing metadata and download
history have separate mutexes. Piece indices and progress counters are atomic.

Each file download uses at most eight workers, limiting descriptors and memory. Each worker
holds at most one roughly 512 KiB response. Hashing uses one 512 KiB buffer regardless of file
size.

Active destination paths are reserved before metadata lookup so concurrent jobs cannot write the
same output. The scheduler retries failed requests with bounded exponential backoff and random
jitter. Cancellation is cooperative: workers stop between requests, the partial file and resume
manifest remain valid, and the destination reservation is released.

## Observability

Each download owns atomic counters plus a mutex-protected snapshot model. The scheduler and
workers update that model without changing piece ordering or peer-selection decisions.
Instrumentation records:

- verified and resumed bytes, pieces, elapsed time, throughput, and ETA;
- every piece's unavailable, available, reserved, downloading, verified, or failed state;
- peer bitmaps, availability counts, trust, throughput, failures, and blacklist state;
- rarest-first queue order, active reservations, and worker-to-piece assignments;
- discovered/responsive peers, active secure requests, and protocol events;
- retries separated into network, authentication, unavailable-piece, and corruption causes;
- rolling speed samples and rare-piece/endgame scheduler decisions;
- microseconds spent in AES-GCM, network/wait, and durable disk/manifest work.

The `stats` command renders text snapshots. The CMake-built FTXUI dashboard renders the same
state as a live piece grid, speed graph, peer table, scheduler view, worker table, and event log.
Completion time is frozen when a download reaches `[C]` or `[F]`, and the TUI automatically
opens an integrity or failure summary.

The TUI keeps sensitive commands out of history, supports command recall for other commands,
scrolls protocol events independently, and exposes cancellation for the selected transfer.

## Automated verification

CTest covers published cryptographic vectors, PBKDF2, quoted command parsing, password/session
state behavior, live two-tracker replication, and clean state after both tracker processes
restart. A process-level client test additionally exercises account/group setup, multi-piece
upload, the AES-GCM peer protocol, reconstruction, final hashing, and byte-for-byte
output comparison. CMake optionally enables AddressSanitizer and UndefinedBehaviorSanitizer for
every project target with `TORRENT_ENABLE_SANITIZERS=ON`.

## Challenges and solutions

- TCP partial transmission: exact-length read/write loops.
- Corrupt data: verify each response before disk write, then verify the whole temporary file.
- Tracker outage: endpoint failover and in-memory queued replication.
- Single-tracker restart: live peer snapshot recovery.
- Concurrent output writes: disjoint `pwrite` offsets.
- Incomplete destination exposure: temporary files and atomic rename.
- Lost replication acknowledgement: idempotent replay behavior.
- Malicious seeders: local evidence-based scoring, heavy integrity penalties, and timed
  blacklisting.
- Slow final pieces: duplicate endgame requests with first-valid-response selection.
- Client crashes: durable per-piece manifests, restart-time SHA1 revalidation, and automatic
  continuation from the missing-piece set.
- Security complexity: tracker-issued file capabilities double as AES keys, avoiding a separate
  peer handshake.

## External resources

The implementation follows the SHA-1 algorithm structure defined by FIPS PUB 180-4. No
external source code or torrent implementation is included.

# Technical report

## Scope

Torrent Atlas implements the assignment’s tracker and peer workflows while keeping one advanced distributed-systems feature: a consistency-aware load balancer in front of two replicated trackers. Metadata is ephemeral by design; file bytes never pass through the tracker tier.

## Consistency model

Stable FNV-1a ownership keeps user and group aggregates deterministic. The LB serializes mutations and trackers replicate each mutation with an origin-specific monotonic sequence. Replicas deduplicate deliveries, buffer gaps, and expose a two-element applied vector. Immediate replication is attempted before success is returned; failure places the operation in a FIFO retry queue.

Snapshot recovery transfers metadata and the applied vector as one checked envelope. The LB returns a recovered shard to its normal owner only when both ready vectors match. A replay result that contradicts local state is treated as replica degradation, not an endlessly retried poison message.

This is intentionally weaker and smaller than Raft: there is one LB, no durable log, no election, and no quorum commit. Within those assumptions it provides deterministic ownership, ordered at-least-once delivery, idempotent replay, and catch-up-gated failback.

## Transfer engine

Files are divided into 512 KiB pieces. The tracker stores the full SHA-1, ordered piece hashes, a random 256-bit capability, and seeder endpoints. Downloaders validate metadata before using piece counts in allocation or arithmetic.

Peers exchange framed AES-256-GCM messages. Authenticated data binds each request and response to its group, file, and nonce. Each received piece must match its SHA-1 before it is committed. A final full-file SHA-1 check runs before the temporary file is renamed.

The scheduler collects peer bitmaps and uses deterministic rarest-first ordering. Parallel workers choose only peers advertising a piece, rotate the starting peer to spread work, and retry failures. Telemetry reports availability, measured throughput, successes, and failure categories without converting them into trust or reputation scores.

Resume manifests record immutable metadata, the temporary path, and a verified-piece bitmap. A resumed download re-hashes every claimed piece. Verified partial pieces are immediately available through the peer service.

## Reliability and safety

- Length-prefixed frames cap allocation at 16 MiB.
- Endpoint and unsigned decimal parsing require full token consumption.
- Ports, hashes, capabilities, piece counts, and snapshot records are validated.
- TCP connect uses nonblocking `connect` plus a deadline and `SO_ERROR` verification.
- RAII descriptors cover shared protocol and key storage paths.
- The client requests cancellation, joins download threads, and joins its peer service on normal exit.
- User-visible tracker collections and peer metrics are sorted for deterministic demonstrations.
- Passwords are PBKDF2-HMAC-SHA256 encoded with random salts and are never logged by the LB.

## Verification

CTest covers parser strictness, frame boundaries, SHA-1 vectors, cryptography, resume manifests, tracker edge cases, replication gaps/duplicates/degradation, tracker integration, LB routing/failover/restart, peer rejection, and a complete encrypted client transfer through the LB. CI runs a release configuration and an AddressSanitizer/UndefinedBehaviorSanitizer configuration on Ubuntu.

## Known limits

The LB is a single point of failure. All tracker state and retry queues are in memory. Tracker traffic assumes a trusted network. SHA-1 remains only for assignment compatibility. The replication model is neither consensus nor a general-purpose CRDT.

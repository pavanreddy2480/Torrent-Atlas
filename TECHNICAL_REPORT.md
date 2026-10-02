# Technical report

## Scope

Torrent Atlas implements the assignment’s tracker and peer workflows while keeping one advanced distributed-systems feature: one write server replicating synchronously to two read servers behind a consistency-aware load balancer. Metadata is ephemeral by design; file bytes never pass through the tracker tier.

## Consistency model

All mutations run on the write server, which assigns each one the next sequence number and sends it to every in-sync read server before replying. Read servers apply entries strictly in order. A duplicate is acknowledged; a gap or an entry that conflicts with local state is answered with `RESYNC`, and the write server replaces that read server's state with a snapshot.

The load balancer sends reads only to read servers whose applied sequence equals the write server's, falling back to the write server itself. That gives read-your-writes consistency through the LB. With the write server down, the LB serves reads from the most advanced read server and refuses writes.

A background loop on the write server checks both read servers every 250 ms and pushes a snapshot to any that is behind, which covers restarts and missed entries. A restarted write server starts by copying the most advanced read server's snapshot.

This is intentionally simpler than consensus: one fixed writer, no election, no durable log.

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

CTest covers parser strictness, frame boundaries, SHA-1 vectors, cryptography, resume manifests, tracker edge cases, replication gaps, duplicates and snapshot resync, three-node tracker integration, LB read/write routing and read/write server failure and restart, peer rejection, and a complete encrypted client transfer through the LB. CI runs a release configuration and an AddressSanitizer/UndefinedBehaviorSanitizer configuration on Ubuntu.

## Known limits

The LB is a single point of failure, and the write server is one for writes. All tracker state is in memory. Tracker traffic assumes a trusted network. SHA-1 remains only for assignment compatibility. There is no leader election: if the write server stays down, the cluster is read-only.

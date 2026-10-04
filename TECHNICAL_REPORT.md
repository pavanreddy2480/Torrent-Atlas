# Technical report

## Scope

Torrent Atlas implements tracker and peer workflows with a Raft-replicated tracker cluster (NuRaft) and direct encrypted peer transfer. File bytes never pass through the tracker tier.

## Consistency model

Every state-changing command is a Raft log entry. The leader fixes the entry's random inputs (salt, session ID) and its timestamp, so the tracker state machine is deterministic and every replica reaches the same state. A client receives `OK` only after a majority has the entry on disk. Reads are served by the leader, so a client always reads its own acknowledged writes.

With three trackers, one failure is tolerated with no loss of acknowledged writes and automatic failover. With two down, the cluster refuses writes instead of diverging. Logs, votes and snapshots are fsynced to disk, so a full restart keeps all metadata.

NuRaft handles elections, log matching and chunked snapshot transfer. This project provides the state machine, durable log and state storage, client-facing routing (`REDIRECT` to the leader), and TLS configuration.

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
- Passwords are PBKDF2-HMAC-SHA256 encoded with random salts, travel only inside the encrypted client channel, and are never logged.

## Verification

CTest covers parser strictness, frame boundaries, SHA-1 vectors, cryptography, resume manifests, tracker edge cases, deterministic replay of log entries, Raft leader election and redirects, leader crash failover, no-quorum write refusal, rejoin and full-cluster restart durability, handshake and replay attacks, peer rejection, and a complete encrypted client transfer through the Raft cluster. CI runs a release configuration and an AddressSanitizer/UndefinedBehaviorSanitizer configuration on Ubuntu.

## Known limits

Three fixed trackers tolerate one failure; membership changes are not exposed. Reads go to the leader only, and an isolated leader may answer reads for up to its 2 s lease. SHA-1 remains only for integrity compatibility. File capabilities are long-lived per-file keys.

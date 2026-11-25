# Technical report

## Scope

Torrent Atlas implements tracker and peer workflows with a single tracker and direct encrypted peer transfer. File bytes never pass through the tracker.

## Tracker

The tracker answers every command from an in-memory `TrackerState`, one lock per command. Nothing is saved to disk: passwords exist only in memory as PBKDF2 hashes, and a restart starts the tracker empty. With a single tracker that is already a single point of failure, so persistence was left out for simplicity; a real deployment would add atomic snapshots or an embedded database.

## Access to files

There is no long-lived per-file key. Each running client makes a random 256-bit peer key that only it and the tracker know. When a member asks for a file, the tracker issues one ticket per seeder, naming the user, group, file and an expiry five minutes ahead, with key HMAC-SHA256(peer key, ticket). Seeders recompute the key, so only tickets the tracker issued, unedited and unexpired, decrypt. Membership changes (`remove_member`, `leave_group`) stop new tickets immediately, and downloads renew their tickets shortly before they expire.

Seeders verify the ticket and decrypt the request before looking up the file, and reply `60|denied` to every request that fails, so a peer reveals nothing about which files it holds to someone without a valid ticket.

## Transfer engine

Files are divided into 2 MiB pieces. The tracker stores the full SHA-256, ordered piece hashes, and each seeder's endpoint and peer key. Downloaders validate metadata before using piece counts in allocation or arithmetic.

Peers exchange framed AES-256-GCM messages, with the nonce, ciphertext and tag written as base64 inside the `|`-separated frame. Authenticated data binds each request to its ticket and each response to the request nonce. Each received piece must match its SHA-256 before it is committed. A final full-file SHA-256 check runs before the temporary file is renamed.

The scheduler collects peer bitmaps and uses deterministic rarest-first ordering. Up to 16 parallel workers (not limited by the number of seeders) choose only peers advertising a piece, start each piece at a different holder to spread work, and retry failures.

Resume needs no extra state: an existing `.part` file is re-hashed piece by piece against the tracker's hashes, and only matching pieces are kept. Verified partial pieces are immediately available through the peer service.

## Reliability and safety

- Length-prefixed frames cap allocation at 16 MiB.
- Endpoint and unsigned decimal parsing require full token consumption.
- Ports, hashes, peer keys, tickets, piece counts, and saved-state records are validated.
- TCP connect uses nonblocking `connect` plus a deadline and `SO_ERROR` verification.
- Sockets, files and OpenSSL objects are owned by RAII classes (`Socket`, `PieceFile`, `OpenSslPtr`).
- The client requests cancellation, joins download threads, and joins its peer service on normal exit.
- User-visible tracker collections are sorted for deterministic demonstrations.
- Passwords are PBKDF2-HMAC-SHA256 encoded with random salts, travel only inside the encrypted client channel, and are never logged or saved.

## Verification

CTest covers parser strictness, frame boundaries, SHA-256 vectors, base64 round trips, cryptography, piece files, tracker commands and access control, member removal, ticket issue and checking (guessed keys, edited, stretched and expired tickets), identical peer rejections, an empty tracker after restart, handshake and replay attacks, and a complete encrypted client transfer. CI runs a release configuration and an AddressSanitizer/UndefinedBehaviorSanitizer configuration on Ubuntu.

## Known limits

One tracker is a single point of failure for logins and new downloads. Tickets already issued stay valid for up to five minutes after a member is removed.

## Design decisions, justified by ablation (2026-11-25)

Each decision was switched off or varied on its own and measured on real
downloads: one tracker, four seeders, a fresh member downloading a 64 MB random
file, median of 5 runs on macOS arm64 (8 cores) over loopback. A second set of
runs adds 5 ms to every seeder reply to mimic network latency. Every downloaded
file was compared byte for byte with its source. Full tables, graphs and raw
rows are in `docs/ablations/`; `bench/run_all.sh` reruns everything.

| Decision | Measured effect | Verdict |
|---|---|---|
| AES-256-GCM on peer transfers | about 2.5 % throughput (419 vs 409 MB/s); also what rejects forged tickets | keep |
| Per-piece hash check | 0.6 % (424 vs 421 MB/s) | keep |
| Whole-file hash check | 1.2 % (413 vs 408 MB/s) | keep |
| SHA-256 instead of SHA-1 | same speed (about 2.6 GB/s each on this CPU); no known collision attacks | switched |
| Hex on the wire | 2.6x slower and 4.6x the CPU of base64 (164 vs 422 MB/s; 1.31 s vs 0.28 s CPU); sends 135 MB instead of 90 MB for a 64 MB file | replaced with base64 |
| Threads capped by seeder count (4 here) | 164 MB/s; 8 threads 219, 16 threads 222; with 5 ms latency 4 threads 99, 16 threads 191 | cap raised to 16, no seeder limit |
| 512 KiB pieces | flat on loopback (144 MB/s at 64 KiB, 165 at 4 MiB); with 5 ms latency 99 MB/s at 512 KiB vs 139 at 2 MiB | 2 MiB |
| Rarest-first | no speed difference when every seeder has the whole file (160 vs 164 vs 162 MB/s) | kept, value is availability, not speed |

Before and after the applied changes (64 MB file, 4 seeders):

| Build | Loopback | 5 ms latency | CPU (s) | Bytes sent |
|---|---|---|---|---|
| before (SHA-1, hex, 512 KiB, threads capped) | 164 MB/s | 100 MB/s | 1.31 | 135 MB |
| after | 485 MB/s | 381 MB/s | 0.35 | 90 MB |

This replaces the earlier 256 MiB, single-seeder measurement (about 15 MiB/s),
which was taken before these changes.

Limits of these measurements: everything ran on one machine over loopback; the
5 ms delay models latency only, not bandwidth limits or packet loss; AES and
SHA are hardware accelerated on this CPU, so older CPUs will show larger
costs; differences under about 3 % are within run-to-run noise; and rarest-first
was not tested with seeders that hold different parts of the file. Raw binary
framing (no text encoding at all) would send 64 MB for a 64 MB file and was not
tried.

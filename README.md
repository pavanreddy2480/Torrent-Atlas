# Torrent Atlas

Torrent Atlas is an interview-sized BitTorrent-style file sharing system written in C++17. It keeps the hard parts visible: replicated tracker metadata, deterministic load balancing, direct peer transfer, framed TCP, AES-256-GCM piece exchange, SHA-1 integrity checks, resumable parallel downloads, rarest-first scheduling, and a command-line client.

## Architecture

```text
clients ── framed TCP ──> load balancer :5000
                              │
              writes ─────────┼───────── reads
                 v            │            v
       write server :6000 ──sync──> read servers :6001, :6002

peer :8001 <──── encrypted piece traffic ────> peer :8002
```

The tracker tier has one write server and two read servers. Clients only talk to the load balancer.

Every state-changing command (`create_user`, `login`, `upload_file`, ...) goes to the write server. It applies the command, gives it the next sequence number, and pushes it to both read servers before answering. So once a client sees `OK`, both in-sync read servers already have the change.

Reads (`list_groups`, `list_files`, `download_file`, ...) are spread round-robin over the read servers that are at the write server's sequence number. A read server that is behind is skipped until it catches up, so reads never return older data than a write the client already saw.

A read server that was down, restarted, or missed an entry is caught up with a full snapshot push from the write server. A restarted write server copies its state from the most up-to-date read server before accepting writes. While the write server is down, reads keep working from the read servers and writes return `ERR write server unavailable`.

For the wire formats and failure-state details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Build and test

Requirements: CMake 3.16+, a C++17 compiler, and OpenSSL.

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For an AddressSanitizer/UndefinedBehaviorSanitizer build:

```sh
cmake -S . -B build-sanitize -DTORRENT_ENABLE_SANITIZERS=ON
cmake --build build-sanitize -j
ctest --test-dir build-sanitize --output-on-failure
```

Build output goes in `build/` (or `build-sanitize/`), which git ignores. Delete it any time; the commands above recreate it.

## Local demo

Committed example configs use LB `5000`, write server `6000`, and read servers `6001` and `6002`. Tracker number 1 is always the write server.

```sh
./build/tracker config/trackers.conf 2
./build/tracker config/trackers.conf 3
./build/tracker config/trackers.conf 1
./build/tracker_lb config/load_balancer.conf
./build/client 127.0.0.1:8001 config/client.conf
./build/client 127.0.0.1:8002 config/client.conf
```

Common commands accept either spaced or underscore spelling:

```text
create user alice secret
login alice secret
create group demo
join group demo
list requests demo
accept request demo bob
upload file demo /path/to/file.bin
list files demo
download file demo file.bin /tmp/file.bin
show downloads
show peers
cancel download file.bin
stop share demo file.bin
logout
quit
```

## Five-minute interview demo

1. Start the three trackers and the LB; point out that clients know only `:5000`.
2. Start two clients, create Alice and Bob, create a group, join it, and accept Bob.
3. Upload a multi-piece file from Alice and download it from Bob. Use `show downloads` and `stats` to show rarest-first progress and throughput.
4. Stop one read server. Reads and writes keep working; restart it and show it is caught up by a snapshot push.
5. Stop the write server. Reads still work and writes are refused. Restart it and show it recovers its state from the read servers.

The tradeoff is deliberately simple: one writer orders every change and replicates synchronously, so reads from in-sync read servers are consistent without a consensus protocol. The cost is that writes stop while the write server is down.

## Transfer behavior

- 4-byte big-endian length-prefixed TCP frames with a 16 MiB cap.
- 512 KiB pieces and parallel rarest-first scheduling.
- AES-256-GCM peer requests and responses with authenticated context.
- Assignment-required SHA-1 per-piece and full-file verification.
- Resume manifests that re-hash claimed pieces before reuse.
- Partial seeding as pieces are verified.
- Retry from another available peer after disconnect, authentication failure, or corruption.
- Explicit cancellation and joined client service lifecycles.
- Factual peer availability, throughput, success, and failure metrics; no trust score or blacklist heuristic.

## Design limits

- The LB is a single point of failure, and so is the write server for writes.
- Tracker state and sequence numbers are in memory. Shutting down all three trackers loses metadata.
- A restarted write server recovers from the most up-to-date read server it can reach. If the only read server reachable at that moment is behind, writes it missed are lost.
- Tracker traffic assumes a trusted network and is not encrypted.
- SHA-1 is retained because the assignment requires it; it is not recommended for new security designs.
- Peer authorization uses tracker-issued file capabilities; it is not an internet-facing identity system.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): architecture, routing, protocol, and recovery.
- [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md): implementation choices and tradeoffs.
- [SECURITY.md](SECURITY.md): threat model and cryptographic notes.
- `design.pdf`: original assignment specification.

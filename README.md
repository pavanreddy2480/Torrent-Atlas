# Torrent Atlas

Torrent Atlas is a BitTorrent-style file sharing system written in C++17: a Raft-replicated tracker cluster, direct encrypted peer transfer, SHA-1 integrity checks, resumable parallel downloads, rarest-first scheduling, and a command-line client.

## Architecture

```text
            client (knows every tracker; follows REDIRECT to the leader)
               │  signed X25519 handshake + AES-256-GCM
     ┌─────────┼─────────┐
     v         v         v
 tracker 1  tracker 2  tracker 3     NuRaft cluster, one elected leader
     └──── mutual TLS (Raft) ────┘   on-disk log, votes and snapshots

peer :8101 <──── AES-256-GCM piece traffic ────> peer :8102
```

The trackers form a [NuRaft](https://github.com/eBay/NuRaft) cluster. One tracker is the elected leader:

- **Writes** (`create_user`, `login`, `upload_file`, ...) are appended to the Raft log. A write gets `OK` only after a majority (2 of 3) has it on disk, so a single crash never loses an acknowledged write.
- **Reads** (`list_groups`, `list_files`, `download_file`, ...) are answered by the leader, so they always reflect every acknowledged write.
- **Followers** answer `REDIRECT <leader>`. Clients remember the leader and retry elsewhere if a tracker is down.
- **Failover:** if the leader dies, the other two elect a new one in about a second. If two of three are down, the last one refuses writes rather than risk losing them.
- **Restarts:** each tracker keeps its log, term, vote and snapshots in its data directory, so a crashed or restarted tracker rejoins and catches up from the leader's log or snapshot.

File bytes never pass through the trackers. Full overview: [PROJECT.md](PROJECT.md). How the distributed parts work: [DESIGN.md](DESIGN.md). Keys and encryption: [SECURITY.md](SECURITY.md).

## Build and test

Requirements: CMake 3.16+, a C++17 compiler, OpenSSL 3, and network access on the first configure (CMake fetches NuRaft and the header-only asio library).

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

`config/cluster.conf` lists the three trackers: client ports `6001`-`6003` and Raft ports `7001`-`7003`.

Create keys once. This writes the cluster CA, one TLS certificate per tracker and the trackers' signing key to `config/keys/` (git-ignored), and writes `config/client.conf` with every tracker address plus the public key clients trust:

```sh
./build/torrent_keygen config/cluster.conf config/keys config/client.conf
```

Start the trackers (each keeps its Raft log in its own data directory), then the clients:

```sh
./build/tracker config/cluster.conf 1 config/keys data/node1
./build/tracker config/cluster.conf 2 config/keys data/node2
./build/tracker config/cluster.conf 3 config/keys data/node3
./build/client 127.0.0.1:8101 config/client.conf
./build/client 127.0.0.1:8102 config/client.conf
```

Set `TORRENT_RAFT_LOG=3` on a tracker to see elections and replication on stderr.

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

1. Start the three trackers; point out that clients know all three and get redirected to the leader.
2. Start two clients, create Alice and Bob, create a group, join it, and accept Bob.
3. Upload a multi-piece file from Alice and download it from Bob. Use `show downloads` and `stats` to show rarest-first progress and throughput.
4. Kill the leader. Within about a second another tracker is leader; reads and writes keep working and nothing acknowledged is lost.
5. Kill a second tracker: writes are refused (no majority). Restart both and show they catch up from the log.

The tradeoff: every write waits for a majority to store it, which costs one network round trip, and the cluster needs 2 of 3 trackers up to accept writes. In return, no acknowledged write is ever lost and failover is automatic.

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

- Three fixed trackers tolerate one failure. Five would tolerate two; membership changes are not wired up.
- Reads are served by the leader only. A leader that is cut off keeps answering reads until its lease expires (about two seconds), so a read in that window can be slightly stale.
- A file capability is a long-lived per-file key: anyone who has it can download or seed that file. See [SECURITY.md](SECURITY.md).
- SHA-1 is kept for piece and file integrity for compatibility; it is not recommended for new designs.
- A seeder that crashes without `logout` stays listed until that user logs out or stops sharing; downloads still succeed by retrying other peers.

## Documentation

- [PROJECT.md](PROJECT.md): complete project overview.
- [DESIGN.md](DESIGN.md): distributed design, with diagrams.
- [SECURITY.md](SECURITY.md): security design, with diagrams.
- [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md): implementation choices and tradeoffs.
- `docs/design.pdf`: original assignment specification.

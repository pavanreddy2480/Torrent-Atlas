# Peer-to-Peer Distributed File Sharing System

This project implements the two-tracker, peer-to-peer file sharing system described in
`design.pdf`. Trackers store metadata only. File bytes move directly between clients.

## Build and execution

Requirements: Linux/macOS, CMake 3.16+, a C++17 compiler, POSIX sockets, pthread support,
`pkg-config`, GMP, Git, and network access during the initial FTXUI configure.

On Debian/Ubuntu:

```sh
sudo apt install g++ cmake make git pkg-config libgmp-dev
```

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Create `tracker_info.txt` with exactly two reachable endpoints:

```text
127.0.0.1:6000
127.0.0.1:7000
```

Run the same tracker executable twice:

```sh
./build/tracker tracker_info.txt 1
./build/tracker tracker_info.txt 2
```

Compatibility binaries `build/tracker1` and `build/tracker2` are also built. Enter `quit`
in a tracker console for a clean shutdown.

Run each client with a unique, externally reachable peer endpoint:

```sh
./build/client 127.0.0.1:8001 tracker_info.txt
./build/client 127.0.0.1:8002 tracker_info.txt
```

Add `--tui` to launch the interactive terminal dashboard:

```sh
./build/client 127.0.0.1:8001 tracker_info.txt --tui
```

The FTXUI dashboard displays live piece state, availability, reservations, worker assignments,
peer trust, throughput, protocol events, and rolling speed. Arrow keys select a download and
all detail panels follow it. Press `:` to open the command bar, `F1` for help, or `F10` to exit.
Passwords are masked in command history. A completion or failure summary opens automatically;
Enter or Escape returns to the dashboard. The full layout targets 120×35 and switches to a
compact layout below that size.

The original Makefile remains available for classic, non-TUI builds:

```sh
make
./client/client 127.0.0.1:8001 tracker_info.txt
```

## Commands

Assignment-style spaced commands and underscore variants are accepted.

```text
create user <user-id> <password>
login <user-id> <password>
create group <group-id>
join group <group-id>
leave group <group-id>
list groups
list requests <group-id>
accept request <group-id> <user-id>
upload file <group-id> <file-path>
list files <group-id>
download file <group-id> <file-name> <destination-path>
resume download <group-id> <file-name> <destination-path>
show downloads
stats
peer_stats
show peers
stop share <group-id> <file-name>
logout
quit
```

`show downloads` uses `[D]` for downloading, `[C]` for complete, and `[F]` for failed. It also
shows rare-piece count, endgame duplicate requests, and integrity failures. `peer_stats` and
`show peers` display trust, throughput, failure counters, and blacklist state. A resumed
download also reports how many pieces survived restart-time revalidation.

`stats` prints a live per-download dashboard:

```text
[D] [group] archive.bin
  progress: 84.4% (54/64 pieces, 27/32 MiB)
  speed: 5.3 MiB/s  elapsed: 5.1s  eta: 0.9s
  peers: 1/1 responsive, 1 requests active, 0 blacklisted
  scheduler: rare=64 resumed=0 endgame-duplicates=0
  reliability: retries=0 network=0 auth=0 unavailable=0 corrupt=0
  security: crypto=2545.2ms network/wait=2431.7ms disk=45.6ms crypto-overhead=50.7%
```

The measurements are collected at the signed-DH/AES/HMAC, socket/wait, and
`pwrite`/`fsync`/manifest boundaries rather than estimated from total runtime.

## Architecture and data structures

- Each tracker owns mutex-protected maps for users, sessions, groups, files, hashes, and
  seeder endpoints.
- A group stores its owner, member set, pending-request set, and files.
- A file stores its size, complete SHA1, ordered piece SHA1 list, and active seeders.
- Each client owns a mutex-protected map of complete and partially downloaded files, including
  a verified-piece bitmap, plus synchronized download and reputation state.
- The client runs a TCP peer server while its command loop remains interactive.

Files are streamed in exactly 512 KiB pieces. Upload hashing uses one fixed-size buffer, so
memory use remains bounded for files up to 1 GiB. A download securely queries every seeder's
piece bitmap, counts availability, and schedules the least-replicated pieces first. Up to eight
workers request disjoint pieces. The final three pieces enter endgame mode: duplicate requests
go to the two best peers and the first verified response wins.

Every verified piece is immediately marked available and served from the partial file. This lets
later clients obtain pieces from peers that are still downloading instead of waiting for them to
finish the complete file.

Peer selection uses a live reputation score based on successful transfers, measured throughput,
network failures, signature/HMAC failures, and SHA1 mismatches. Authentication and integrity
failures carry heavy penalties. Three such failures blacklist a peer for five minutes. Network
timeouts reduce preference but do not immediately blacklist a potentially overloaded peer.

Peer piece traffic is protected by signed ephemeral Diffie-Hellman, manual 2048-bit ElGamal
signatures, AES-256-CBC encryption, and HMAC-SHA256 integrity. Requests include timestamps
and cached nonces to reject replay. See [SECURITY.md](SECURITY.md).

Each decrypted piece is SHA1-verified before `pwrite` writes it. A failed or corrupt response is
retried against other peers. The completed temporary file is streamed through SHA1 again and
atomically renamed to the destination only after the full-file hash matches.

Downloads use stable `<destination>.part` and `<destination>.resume` files. After each verified
piece is flushed with `fsync`, an atomic mode-0600 manifest records the verified bitmap and
immutable file metadata. `download file` resumes automatically when a matching manifest
exists; `resume download` and `resume_download` make that intent explicit. On restart, every
recorded piece is SHA1-checked again before it is trusted or advertised.

## Network protocol

All three communication paths use TCP:

1. Client to tracker: commands, authentication, metadata, and peer discovery.
2. Tracker to tracker: ordered mutation replication and state recovery.
3. Client to client: encrypted, authenticated direct piece requests and responses.

Every message is framed as:

```text
uint32 payload_length_in_network_byte_order
payload_length bytes
```

`readExact` and `writeExact` loop over partial `recv`/`send` operations and handle `EINTR`.
Frames larger than 16 MiB are rejected. Socket send/receive timeouts bound failed connections.
Tracker responses begin with `OK`, `ERR`, or `META`. Secure peer messages use opcodes 20
(signed ephemeral hello), 25 (signed ephemeral response), 21 (encrypted request), 30
(authenticated encrypted result), and 60 (rejection).

Tracker requests carry a 64-bit session token. File names are hex encoded in protocol fields,
allowing binary-safe parsing without delimiter ambiguity.

## Tracker synchronization

Both trackers accept all operations. Successful state-changing commands are:

1. applied under the tracker-state mutex;
2. appended to an in-memory FIFO synchronization queue;
3. retried in order until the peer acknowledges them.

Tracker metadata is intentionally ephemeral. Stopping both trackers clears users, sessions,
groups, files, and pending replication. If one tracker restarts while its peer remains running,
it requests the peer's current in-memory snapshot so failover remains usable within that running
deployment. Session IDs include a tracker-specific prefix, preventing collisions between the
two independent token generators.

Clients try their preferred tracker first and automatically fail over to the second endpoint.

## Assumptions and limitations

- User IDs and group IDs contain no whitespace. File paths containing whitespace are not
  accepted by the interactive parser.
- A group owner cannot leave, because owner-only request management otherwise has no defined
  successor in the specification.
- Tracker metadata is not persisted. Restarting both trackers starts a clean deployment.
- Contradictory writes accepted independently on both sides of a network partition do not use
  consensus. Normal ordered updates converge, but conflicting simultaneous account/group
  creation requires administrative cleanup.
- There is no peer heartbeat. A crashed client's stale endpoint can remain advertised until
  logout/recovery; download workers tolerate it by trying other seeders.
- Tracker-client metadata traffic is the trust anchor but is not encrypted or signed. Secure
  Internet deployment requires pinned tracker signing keys.
- Valid completed downloads remain on disk even if both trackers are unavailable when
  re-seeder registration is attempted.
- Resume manifests contain file capabilities and therefore use mode 0600. Protect the client
  account and local filesystem accordingly.

## Testing

Recommended functional sequence:

1. Start two trackers and three clients.
2. Create two users, create a group, request membership, list requests, and accept.
3. Upload files sized 0 bytes, less than 512 KiB, exactly 512 KiB, and multiple pieces.
4. Download to another client and compare with `sha1sum`/`shasum` and `cmp`.
5. Start two downloads simultaneously and inspect `show downloads`.
6. Stop one tracker and continue issuing commands through client failover.
7. Restart both trackers and verify users and groups have been cleared.
8. Stop one seeder during a multi-peer transfer and confirm another peer supplies the piece.
9. Corrupt a seeder's local source after upload and verify the downloader rejects its pieces.
10. Keep one valid seeder online: verify three corrupt responses blacklist the malicious peer,
    the download completes through the valid peer, and `peer_stats` reports the evidence.
11. Start a second downloader while the first is active and verify it receives pieces from the
    first downloader's partial-piece bitmap.
12. Kill a downloader after several pieces, restart it, log in, and run `resume download`.
    Confirm progress continues from the verified count.
13. Modify bytes in a `.part` file before resuming and confirm the affected piece is rejected and
    fetched again.
14. Run `stats` repeatedly during a multi-peer transfer and confirm progress, active requests,
    throughput, ETA, failure counters, and cryptographic overhead change live.

See [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for design rationale and algorithm details.

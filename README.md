# Torrent Atlas

Torrent Atlas is a BitTorrent-style file sharing system written in C++17: a tracker for accounts, groups and file metadata, direct encrypted peer transfer, SHA-1 integrity checks, resumable parallel downloads, rarest-first scheduling, and a command-line client.

## Architecture

```text
                       tracker      users, groups, files; saves tracker.state
                          ▲         after every change
                          │  signed X25519 handshake + AES-256-GCM
              ┌───────────┴───────────┐
              │                       │
         peer :8101 ◀── pieces ──▶ peer :8102
                    ticket + AES-256-GCM
```

- **The tracker** holds the metadata and answers every client command. It saves its state to disk (atomically, password hashes only) after each change, so a restart loses nothing.
- **Peers** send file pieces directly to each other. A seeder serves only requests carrying a ticket the tracker issued, in the last five minutes, to a current member of the group. Removing someone from a group (`remove member`) or leaving it stops their tickets.

File bytes never pass through the tracker. Full overview: [PROJECT.md](PROJECT.md). How it works: [DESIGN.md](DESIGN.md). Keys and encryption: [SECURITY.md](SECURITY.md).

## Build and test

Requirements: CMake 3.16+, a C++17 compiler and OpenSSL 3. On macOS with Homebrew, add `-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3` to each first `cmake -S` command.

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

Create the tracker's key once. This writes its signing key to `config/keys/` and writes `config/client.conf` with the tracker's address plus the public key clients trust (both git-ignored):

```sh
./build/torrent_keygen 127.0.0.1:6000 config/keys config/client.conf
```

Start the tracker (it keeps its state in `data/`), then the clients:

```sh
./build/tracker 127.0.0.1:6000 config/keys data
./build/client 127.0.0.1:8101 config/client.conf
./build/client 127.0.0.1:8102 config/client.conf
```

Common commands accept either spaced or underscore spelling:

```text
create user alice secret
login alice secret
create group demo
join group demo
list requests demo
accept request demo bob
remove member demo bob
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

1. Start the tracker and two clients. Create Alice and Bob, create a group, join it, and accept Bob.
2. Upload a multi-piece file from Alice and download it from Bob. Use `show downloads` and `stats` to show rarest-first progress and throughput.
3. Kill the tracker and start it again: groups, files and logins are all still there.
4. `remove member demo bob` from Alice: Bob's next `download file` is refused, and Alice's peer stops accepting his tickets once they expire.

## Transfer behavior

- 4-byte big-endian length-prefixed TCP frames with a 16 MiB cap.
- 512 KiB pieces and parallel rarest-first scheduling.
- Tracker-issued, five-minute peer tickets; AES-256-GCM peer requests and responses under each ticket's key.
- One identical `60|denied` for every rejected peer request, so peers don't reveal which files they hold.
- Assignment-required SHA-1 per-piece and full-file verification.
- Resume manifests that re-hash claimed pieces before reuse.
- Partial seeding as pieces are verified.
- Retry from another available peer after disconnect, authentication failure, or corruption.
- Explicit cancellation and joined client service lifecycles.
- Factual peer availability, throughput, success, and failure metrics; no trust score or blacklist heuristic.

## Design limits

- One tracker: while it is down nobody can log in or start a download. Transfers already running continue.
- Removing a member takes effect at seeders when that member's tickets expire, within five minutes.
- SHA-1 is kept for piece and file integrity for compatibility; it is not recommended for new designs.
- A seeder that crashes without `logout` stays listed until that user logs out or stops sharing; downloads still succeed by retrying other peers.

## Documentation

- [PROJECT.md](PROJECT.md): complete project overview.
- [DESIGN.md](DESIGN.md): design, with diagrams.
- [SECURITY.md](SECURITY.md): security design, with diagrams.
- [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md): implementation choices and tradeoffs.
- `docs/design.pdf`: original assignment specification.

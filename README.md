# Torrent Atlas

Torrent Atlas is a terminal-based, two-tracker distributed file sharing system. It separates
metadata coordination from file transfer: trackers manage users, groups, sessions, and seeder
advertisements, while clients exchange file pieces directly with one another.

The project is built around three goals:

- practical peer-to-peer file sharing with direct client-to-client transfers;
- a responsive terminal dashboard for live swarm visibility and control;
- a simple shared-key security model for encrypted peer traffic.

## Screenshots

During an active transfer:

![Torrent Atlas during a transfer](images/durning.png)

After completion:

![Torrent Atlas after completion](images/after.png)

## Features

- Two independent trackers with in-memory metadata replication and failover.
- Direct client-to-client piece transfer encrypted with AES-256-GCM.
- Tracker-issued 256-bit file capabilities used for authorization and peer encryption.
- Piece-level scheduling with rare-piece prioritization and endgame duplication.
- Resume support with durable `.part` and `.resume` files.
- Live telemetry for progress, availability, throughput, peer trust, and protocol events.
- Command-line mode and an FTXUI-based interactive TUI.
- Password verification, session handling, and peer encryption backed by OpenSSL.

## Repository Layout

```text
.
├── client/              # Client implementation, storage, telemetry, and TUI model
├── common/              # Shared protocol, crypto, parsing, and hashing utilities
├── images/              # README screenshots
├── tests/               # Unit and integration tests
├── tracker/             # Tracker implementations and shared tracker state
├── CMakeLists.txt       # Primary build
├── Makefile             # Classic build and test targets
├── README.md            # This file
├── SECURITY.md          # Protocol and threat-model notes
└── TECHNICAL_REPORT.md  # Design rationale and implementation details
```

Build outputs are written to `build/` for CMake or `bin/` for the classic Makefile.

## Requirements

- Linux or macOS
- C++17 compiler
- CMake 3.16 or newer
- POSIX sockets and pthread support
- `pkg-config`
- OpenSSL 3.x
- Git
- Network access during the initial FTXUI fetch

On Debian or Ubuntu:

```sh
sudo apt install g++ cmake make git pkg-config libssl-dev
```

## Build

Recommended build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Classic Makefile build:

```sh
make
```

## Test

Run the full CTest suite:

```sh
ctest --test-dir build --output-on-failure
```

Run the Makefile-specific checks:

```sh
make security-test
make tracker-state-test
make command-parser-test
```

## Run The System

Create `tracker_info.txt` with exactly two tracker endpoints:

```text
127.0.0.1:6000
127.0.0.1:7000
```

Start the two trackers:

```sh
./build/tracker tracker_info.txt 1
./build/tracker tracker_info.txt 2
```

Compatibility binaries are also available:

```sh
./build/tracker1 tracker_info.txt 1
./build/tracker2 tracker_info.txt 2
```

Start one client per peer endpoint:

```sh
./build/client 127.0.0.1:8001 tracker_info.txt
./build/client 127.0.0.1:8002 tracker_info.txt
```

Launch the TUI version with:

```sh
./build/client 127.0.0.1:8001 tracker_info.txt --tui
```

The classic Makefile build uses the same command shape, but the binary is in `bin/`:

```sh
./bin/client 127.0.0.1:8001 tracker_info.txt
```

## Client Commands

Spaced commands and underscore variants are both accepted.

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
cancel download <file-name>
show downloads
stats
peer_stats
show peers
stop share <group-id> <file-name>
logout
quit
```

Examples with quoted paths:

```text
upload file demo "documents/final report.pdf"
download file demo "final report.pdf" "/tmp/final report.pdf"
```

## Workflow

1. Create a user and log in on the seeder client.
2. Create a group and upload a file.
3. On the downloader client, create a user, log in, and join the group.
4. Accept the request on the seeder client.
5. Start the download and watch the live telemetry in `stats` or the TUI.
6. Verify the result with `cmp`, `sha1sum`, or `shasum`.

## Architecture

```mermaid
flowchart LR
    subgraph Control["Control plane: metadata and authorization"]
        T1["Tracker 1<br/>users, groups, files, sessions"]
        T2["Tracker 2<br/>replicated in-memory state"]
        T1 <-->|"asynchronous replication<br/>and snapshot recovery"| T2
    end

    subgraph Peers["Data plane: direct peer transfer"]
        S["Seeder client<br/>peer server + local file"]
        D["Downloader client<br/>scheduler + partial file"]
    end

    S -->|"login, upload metadata,<br/>endpoint, hashes, capability"| T1
    D -->|"login, group membership,<br/>download metadata request"| T2
    T2 -->|"piece hashes, seeder endpoint,<br/>256-bit file capability"| D
    D -->|"AES-256-GCM encrypted<br/>BITMAP / GET request"| S
    S -->|"AES-256-GCM encrypted<br/>bitmap / piece response"| D
    D -->|"SHA-1 verification,<br/>pwrite, resume manifest"| F["Completed file"]
```

Trackers coordinate access but do not relay file data. Clients contact either tracker for
metadata and authorization, then communicate directly for piece transfer. If one tracker is
unavailable, clients fail over to the other.

### Download data flow

1. The tracker verifies that the downloader belongs to the group.
2. It returns piece hashes, seeder endpoints, and the file's random 256-bit capability.
3. The downloader uses the capability as the AES-256-GCM key.
4. The downloader requests encrypted bitmaps, schedules rare pieces first, and downloads pieces
   directly from seeders.
5. Each decrypted piece is checked against its SHA-1 hash before being written.
6. After all pieces pass, the complete file is hashed and atomically moved into place.

## Security Model

The peer protocol uses one simple shared-key design:

- the tracker gives authorized members a random 256-bit file capability;
- peers use that capability as an AES-256-GCM key;
- AES-GCM uses a fresh random nonce for each request and response;
- AES-GCM encrypts peer traffic and rejects modified ciphertext or metadata;
- existing SHA-1 piece hashes verify downloaded file contents.

Tracker passwords are stored as salted PBKDF2-HMAC-SHA256 verifiers. Peer identity keys are not
required. Tracker traffic is not encrypted, so the current design assumes the trackers and
clients run on a trusted network.

For the deeper security notes, see [SECURITY.md](SECURITY.md).

## Storage and Scheduling

- Trackers keep users, sessions, groups, files, and seeders in memory.
- Clients keep completed downloads, partial downloads, resume manifests, and peer reputation.
- Piece requests are scheduled by rarity first, then by live reputation and throughput.
- Verified pieces are written immediately, exposed to the swarm, and revalidated on resume.
- The final file is committed only after a full-file SHA1 check succeeds.

## Testing Notes

The repository includes unit and integration coverage for:

- AES-GCM and password-derivation primitives;
- command parsing;
- tracker state behavior;
- tracker-to-tracker replication and restart recovery;
- full client-to-client download flow.

The best end-to-end check is the integration test plus a manual transfer between two clients.

## Documentation

- [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) for design rationale and protocol details.
- [SECURITY.md](SECURITY.md) for the threat model and cryptographic choices.
- `design.pdf` for the original specification the project implements.

## Notes

- User IDs and group IDs must not contain whitespace.
- File paths may be quoted or backslash-escaped.
- Tracker metadata is ephemeral and clears when both trackers stop.
- Resume manifests include file capabilities and are written with restrictive permissions.

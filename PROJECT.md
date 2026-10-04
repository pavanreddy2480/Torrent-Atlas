# Torrent Atlas: project overview

Torrent Atlas is a peer-to-peer file sharing system written in C++17. Users form groups and share files inside them. Files never sit on a central server; they move directly between the users' machines, in pieces, from several peers at once. A small cluster of **trackers** stores only metadata: who the users are, which groups exist, who is in them, which files are shared and who holds them.

The project focuses on three things:

1. **Correct file transfer:** every piece is hash-checked, downloads resume after a crash, and pieces come from several peers in parallel.
2. **A tracker tier that survives failures:** three trackers replicate every change with the Raft consensus algorithm. One can crash at any time without losing data or stopping the service.
3. **Security on every link:** client-to-tracker, tracker-to-tracker and peer-to-peer traffic are all encrypted and authenticated.

Related documents:

- [DESIGN.md](DESIGN.md): how the distributed parts work, and why.
- [SECURITY.md](SECURITY.md): keys, encryption, handshakes and threat model.
- [README.md](README.md): quick start.

---

## 1. The big picture

```text
 ┌──────────────────────────── tracker cluster ────────────────────────────┐
 │                                                                         │
 │   ┌───────────┐  Raft over mTLS  ┌───────────┐  Raft over mTLS  ┌───────────┐
 │   │ tracker 1 │◀────────────────▶│ tracker 2 │◀────────────────▶│ tracker 3 │
 │   │ (leader)  │                  │(follower) │                  │(follower) │
 │   └─────▲─────┘                  └─────▲─────┘                  └─────▲─────┘
 │         │ disk: log, votes, snapshots  │                              │
 └─────────┼──────────────────────────────┼──────────────────────────────┼─────
           │ encrypted request / reply    │ "REDIRECT to tracker 1"      │
           │                              │                              │
     ┌─────┴──────┐                 ┌─────┴──────┐                 ┌─────┴──────┐
     │  client A  │◀═══ pieces ════▶│  client B  │◀═══ pieces ════▶│  client C  │
     │ (seeder)   │   AES-256-GCM   │(downloader)│   AES-256-GCM   │ (seeder)   │
     └────────────┘                 └────────────┘                 └────────────┘
```

- **Clients** talk to the tracker cluster for metadata (login, groups, file lists, where a file lives), and to each other for file data.
- **Trackers** keep the metadata consistent across three machines. One tracker is the elected **leader**. It handles every request, and the other two keep identical copies.
- **File data** goes only from peer to peer, encrypted with a per-file key that the tracker gives to group members.

---

## 2. Components

### 2.1 Tracker (`tracker/`)

| File | Role |
| --- | --- |
| `tracker.cpp` | Entry point: `tracker <cluster.conf> <node-id> <keys-dir> <data-dir>` |
| `tracker_state.hpp` | The metadata itself: users, password hashes, sessions, login lockouts, groups, membership, files and seeders. Deterministic, so every replica computes the same result. |
| `raft_tracker.hpp` | Runs the tracker as a NuRaft node. Turns writes into log entries, answers reads, redirects clients to the leader, configures mutual TLS. |
| `raft_storage.hpp` | Durable Raft storage: log file, term/vote, membership, snapshots. |

### 2.2 Client (`client/`)

| File | Role |
| --- | --- |
| `client.cpp` | Command shell, tracker requests (with leader redirect), the peer server that seeds files, and the parallel downloader. |
| `download_storage.cpp` | Hashing files, writing pieces, and resume manifests. |
| `network_utils.cpp` | Reads `client.conf` (tracker list plus the cluster's public key). |
| `command_utils.cpp` | Accepts both `create user` and `create_user` spellings, and hides passwords when logging commands. |
| `telemetry.cpp` | Timing, retry back-off and failure counters for `stats`. |

### 2.3 Shared code (`common/`)

| File | Role |
| --- | --- |
| `protocol.hpp` | Length-prefixed TCP framing, endpoint parsing, hex helpers, and the list of commands that change state. |
| `secure_crypto.hpp` | OpenSSL wrappers: random bytes, PBKDF2, AES-256-GCM, SHA-256, HMAC, Ed25519, X25519. |
| `secure_channel.hpp` | The client-to-tracker handshake and the sealed request and reply. |
| `cluster_config.hpp` | Parses `cluster.conf`. |
| `cluster_keys.hpp` | Creates the CA, node certificates, signing key and `client.conf`. |
| `sha1.hpp` | SHA-1 for piece and file integrity. |
| `command_parser.hpp` | Splits shell input, handling quotes and escapes. |

### 2.4 Tools (`tools/`)

`torrent_keygen <cluster.conf> <keys-dir> <client.conf>` creates every key and certificate a deployment needs (see [SECURITY.md](SECURITY.md#3-keys-and-who-holds-them)).

### 2.5 Third-party code

| Library | Used for | How it arrives |
| --- | --- | --- |
| OpenSSL 3 | All cryptography and TLS | System package |
| [NuRaft](https://github.com/eBay/NuRaft) (eBay) | Raft consensus: elections, replication, snapshots | CMake `FetchContent` |
| asio (standalone) | NuRaft's networking | CMake `FetchContent` |

---

## 3. What a user can do

The client prints a `>` prompt. Every command accepts both `create user` and `create_user` spellings.

| Command | What it does | Who may run it |
| --- | --- | --- |
| `create user <name> <password>` | Register an account | Anyone |
| `login <name> <password>` | Start a session | Anyone with an account |
| `logout` | End the session and stop sharing all files | Logged-in users |
| `create group <group>` | Create a group; you become its owner | Logged-in users |
| `join group <group>` | Ask to join | Logged-in users |
| `list requests <group>` | See pending join requests | Group owner |
| `accept request <group> <user>` | Admit a user | Group owner |
| `leave group <group>` | Leave (your shares in it are removed) | Members (not the owner) |
| `list groups` | All groups | Logged-in users |
| `upload file <group> <path>` | Share a file with the group | Members |
| `list files <group>` | Files shared in the group | Members |
| `download file <group> <name> <dest>` | Download from the group's peers | Members |
| `resume download <group> <name> <dest>` | Continue an interrupted download | Members |
| `show downloads` | `[D]` downloading, `[C]` complete, `[F]` failed, with progress | Local |
| `stats` | Speed, ETA, peers, retries, time spent in crypto, network and disk | Local |
| `show peers` | Per-peer successes, failures and throughput | Local |
| `cancel download <name>` | Stop a download; resume data is kept | Local |
| `stop share <group> <name>` | Stop seeding a file | Seeder |
| `quit` | Exit the client | Local |

---

## 4. Life of a file

### 4.1 Upload (sharing)

```text
 client A                                   tracker leader
    │ 1. read file, SHA-1 each 512 KiB piece
    │    and the whole file
    │ 2. pick a random 256-bit capability
    │    (the file's encryption key)
    │ 3. upload_file group name size hash      ──▶  append to Raft log
    │    capability piece-hashes my-ip my-port       commit on 2 of 3 trackers
    │                                          ◀──  OK file shared <capability>
    │ 4. start serving pieces from the peer server
```

If the same file (same size and hashes) is already shared in the group, the tracker keeps the original capability and returns it, so every seeder of a file uses the same key.

### 4.2 Download

```text
 client B                     tracker leader                 seeders A, C
    │ download_file group name ──▶ checks membership
    │ ◀── META size hash capability piece-hashes peer-list
    │
    │ BITMAP request (encrypted) ───────────────────────────────▶ each seeder
    │ ◀─────────────────────────────── which pieces each one has
    │
    │ sort missing pieces: rarest first (fewest holders), then by index
    │ start up to 8 workers; each takes the next piece:
    │      GET piece i (encrypted) ─────────────────────────────▶ a holder
    │      ◀──────────────────────────────── piece bytes (encrypted)
    │      SHA-1 matches? ── no ─▶ try another holder (3 rounds, back-off)
    │            │ yes
    │      write piece, fsync, update resume manifest,
    │      start seeding this piece to others immediately
    │
    │ all pieces done ─▶ SHA-1 of the whole file ─▶ rename .part to final name
    │ upload_file (now a full seeder) ──▶ tracker
```

- **Rarest first:** pieces that few peers hold are fetched first, so they spread before those peers leave.
- **Partial seeding:** as soon as a piece is verified, the downloader serves it to others.
- **Resume:** a manifest (`<dest>.resume`, mode `0600`) records which pieces are verified. On resume, every claimed piece is re-read and re-hashed before it is trusted.
- **Integrity:** a piece is written only if its SHA-1 matches the tracker's hash, and the file is renamed into place only if the full-file SHA-1 matches.

---

## 5. Repository layout

```text
.
├── CMakeLists.txt          build: client, tracker, torrent_keygen, tests
├── config/
│   ├── cluster.conf        the three trackers: id, client address, Raft address
│   └── client.conf         tracker addresses (+ public key after keygen)
├── client/                 client program
├── tracker/                tracker program (Raft node)
├── common/                 shared protocol, crypto and config code
├── tools/keygen.cpp        key and certificate generator
├── tests/                  unit and integration tests (CTest)
├── PROJECT.md              this file
├── DESIGN.md               distributed design
├── SECURITY.md             security design
├── TECHNICAL_REPORT.md     implementation notes and trade-offs
└── README.md               quick start
```

`config/keys/` (secret keys) and `data/` (tracker storage) are created at run time and ignored by git.

---

## 6. Build, run, test

### Build

Requirements: CMake 3.16+, a C++17 compiler and OpenSSL 3. The first configure needs internet access to fetch NuRaft and asio.

```sh
cmake -S . -B build
cmake --build build -j
```

### Run a local cluster

```sh
# once: keys, certificates and client.conf
./build/torrent_keygen config/cluster.conf config/keys config/client.conf

# three trackers, in three terminals
./build/tracker config/cluster.conf 1 config/keys data/node1
./build/tracker config/cluster.conf 2 config/keys data/node2
./build/tracker config/cluster.conf 3 config/keys data/node3

# clients, each with its own peer address
./build/client 127.0.0.1:8101 config/client.conf
./build/client 127.0.0.1:8102 config/client.conf
```

Type `quit` in a tracker's terminal to stop it. Set `TORRENT_RAFT_LOG=3` to print elections and replication.

### Test

```sh
ctest --test-dir build --output-on-failure
```

| Test | Covers |
| --- | --- |
| `security_tests` | SHA-1, SHA-256, HMAC and PBKDF2 known answers; AES-GCM tampering; Ed25519; X25519; handshake success and wrong-key failure |
| `tracker_state_tests` | Tracker commands; access control (login, member-only, owner-only); lockout; snapshots; replicas agree when applying the same log |
| `command_parser_tests` | Quoting and escaping |
| `protocol_tests` | Frame and endpoint parsing |
| `download_storage_tests` | Hashing, piece writes, resume manifests |
| `tracker_integration_tests` | 3-node cluster: redirects, leader crash, no-majority refusal, rejoin, full restart, plain-text, wrong-key and replay attacks, non-TLS Raft peer |
| `client_integration_tests` | Full upload and encrypted multi-peer download through the cluster, `show downloads`, retry after a seeder leaves |
| `peer_rejection_test` | Malformed and unauthorized peer requests |

CI (`.github/workflows/ci.yml`) runs a release build and an AddressSanitizer/UBSan build on every push.

---

## 7. Limits and future work

- **Fixed membership:** three trackers tolerate one failure. Five would tolerate two. Adding or removing trackers while running is not wired up.
- **Leader-only reads:** a leader that is cut off may answer reads for up to about 2 s before it steps down.
- **Per-file keys:** anyone who holds a file capability can download or seed that file.
- **Crashed seeders stay listed** until that user logs out, stops sharing or leaves the group. Downloads still succeed by retrying other peers.
- **SHA-1 for integrity** is kept for compatibility; SHA-256 would be the modern choice.

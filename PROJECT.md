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

Each program is split into small classes, one per job, with a header (`.hpp`) for the interface and a source file (`.cpp`) for the code. The build compiles them into three libraries (`torrent_common`, `tracker_core`, `client_core`) that the programs and the tests link against.

### 2.1 Tracker (`tracker/`)

| File | Role |
| --- | --- |
| `main.cpp` | Entry point: `tracker <cluster.conf> <node-id> <keys-dir> <data-dir>`. Loads config and keys, starts a `RaftNode`, and serves clients with a `TcpServer` over `SecureChannel`. |
| `tracker_state` | `TrackerState`: users, password hashes, sessions, login lockouts, groups, membership, files and seeders. Every command is one method, picked from a table that also says whether it needs a login and whether it changes state. Deterministic, so every replica computes the same result. |
| `state_snapshot.cpp` | `TrackerState::serialize` and `restore`: the snapshot text format. |
| `password` | PBKDF2 password hashing and checking. |
| `log_command` | `LogCommand`: a client command plus its salt, session ID and time, as stored in the Raft log. |
| `raft_node` | `RaftNode`: runs the tracker as a NuRaft node. Turns writes into log entries, answers reads, redirects clients to the leader, configures mutual TLS. |
| `state_machine` | `TrackerStateMachine`: NuRaft's view of `TrackerState`. Applies committed entries and saves, sends and installs snapshots. |
| `raft_storage` | `FileLogStore` and `FileStateManager`: the durable Raft log, term/vote and membership. |
| `storage_io` | fsynced and atomic file writes, and NuRaft buffer conversions. |

### 2.2 Client (`client/`)

| File | Role |
| --- | --- |
| `main.cpp` | Entry point: `client <peer IP:PORT> <client.conf>`. |
| `client` | `Client`: the command prompt. Owns every other part and sends each command to the right one. |
| `command_line` | `CommandLine`: splits typed input (quotes, escapes) and accepts both `create user` and `create_user`. |
| `tracker_client` | `TrackerClient`: requests to the tracker cluster, following leader redirects and keeping the session ID. |
| `shared_files` | `SharedFiles`: the files this client seeds, complete or partly downloaded. |
| `peer_server` | `PeerServer`: answers other peers' bitmap and piece requests. |
| `peer_client` | `PeerClient`: asks a seeder for its bitmap or a piece and checks the piece hash. |
| `peer_protocol` | The encrypted peer-to-peer message format, shared by both sides. |
| `peer_stats` | `PeerStats`: per-peer successes, failures and speed for `show peers`. |
| `download` | `Download`: one download, from resume check to rarest-first parallel fetch to the final hash check. |
| `download_manager` | `DownloadManager`: starts, lists, measures and cancels downloads. |
| `piece_file` | `PieceFile`: reads, writes and hashes a file one 512 KiB piece at a time. |
| `resume_manifest` | `ResumeManifest`: the `<dest>.resume` file that lets a download continue. |
| `local_file.hpp` | `LocalFile`: a seeded file's path, metadata and available pieces. |

### 2.3 Shared code (`common/`)

| File | Role |
| --- | --- |
| `net` | `Endpoint` (IPv4 address and port) and `Socket` (RAII socket with length-prefixed frames). |
| `tcp_server` | `TcpServer`: accepts connections and handles each one on its own thread. Used by the tracker and the peer server. |
| `crypto` | OpenSSL wrappers: random bytes, SHA-1, SHA-256, PBKDF2, AES-256-GCM, Ed25519, X25519. |
| `secure_channel` | `SecureChannel`: the client-to-tracker handshake and the sealed request and reply. |
| `file_metadata` | `FileMetadata`: a file's size, hashes and capability, with validation. |
| `cluster_config` | `ClusterConfig`: parses `cluster.conf`. |
| `client_config` | `ClientConfig`: reads and writes `client.conf`. |
| `cluster_keys` | Creates the CA, node certificates, signing key and `client.conf`; `NodeKeys` loads one node's keys. |
| `encoding` | Hex, decimal parsing, split and join. |
| `freshness.hpp` | The five-minute timestamp window for handshakes and peer requests. |
| `openssl_ptr.hpp` | `std::unique_ptr` for OpenSSL objects. |

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
| `stats` | Progress, speed, ETA, responsive peers and retries for each download | Local |
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
├── common/                 shared networking, crypto and config code
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
| `net_tests` | Endpoint, number and hex parsing; frame limits |
| `security_tests` | SHA-1, SHA-256 and PBKDF2 known answers; AES-GCM tampering; Ed25519; X25519; handshake success and wrong-key failure |
| `command_line_tests` | Quoting, escaping and two-word command names |
| `resume_tests` | Resume manifests, file hashing, piece reads and writes |
| `tracker_state_tests` | Tracker commands; access control (login, member-only, owner-only); lockout; snapshots; replicas agree when applying the same log |
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

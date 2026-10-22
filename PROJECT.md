# Torrent Atlas: project overview

Torrent Atlas is a peer-to-peer file sharing system written in C++17. Users form groups and share files inside them. Files never sit on a central server; they move directly between the users' machines, in pieces, from several peers at once. A single **tracker** stores only metadata: who the users are, which groups exist, who is in them, which files are shared and who holds them.

The project focuses on three things:

1. **Correct file transfer:** every piece is hash-checked, downloads resume after a crash, and pieces come from several peers in parallel.
2. **Access that follows group membership:** a seeder serves only people holding a short-lived ticket the tracker issued for them, so leaving or being removed from a group cuts access off.
3. **Security on every link:** client-to-tracker and peer-to-peer traffic are encrypted and authenticated, and the tracker never stores a password.

Related documents:

- [DESIGN.md](DESIGN.md): how the parts work, and why.
- [SECURITY.md](SECURITY.md): keys, encryption, handshakes and threat model.
- [README.md](README.md): quick start.

---

## 1. The big picture

```text
                        ┌───────────────────────────┐
                        │          tracker          │
                        │  disk: tracker.state      │
                        └──▲──────────▲──────────▲──┘
                           │ encrypted request / reply, peer tickets
     ┌─────────────────────┘          │          └─────────────────────┐
     │                                │                                │
 ┌───┴────────┐                 ┌─────┴──────┐                 ┌───────┴────┐
 │  client A  │◀═══ pieces ════▶│  client B  │◀═══ pieces ════▶│  client C  │
 │ (seeder)   │   AES-256-GCM   │(downloader)│   AES-256-GCM   │ (seeder)   │
 └────────────┘                 └────────────┘                 └────────────┘
```

- **Clients** talk to the tracker for metadata (login, groups, file lists, where a file lives), and to each other for file data.
- **The tracker** keeps the metadata and saves it to disk after every change.
- **File data** goes only from peer to peer. Each request carries a ticket the tracker issued to that member for that seeder, and is encrypted under the ticket's key.

---

## 2. Components

Each program is split into small classes, grouped into subfolders by area, one per job, with a header (`.hpp`) for the interface and a source file (`.cpp`) for the code. The build compiles them into three libraries (`torrent_common`, `tracker_core`, `client_core`) that the programs and the tests link against.

### 2.1 Tracker (`tracker/`)

`state/` holds the tracker's data and commands; the rest serves them and saves them.

| File | Role |
| --- | --- |
| `main.cpp` | Entry point: `tracker <IP:PORT> <keys-dir> <data-dir>`. Loads the identity key and saved state, and serves clients with a `TcpServer` over `SecureChannel`. |
| `tracker_service` | `TrackerService`: turns one decrypted request into a `TrackerState` command, and saves the state after every command that changes it. |
| `state_file` | `StateFile`: reads `tracker.state` and replaces it atomically (temporary file, fsync, rename). |
| `state/tracker_state` | `TrackerState`: users, password hashes, sessions, login lockouts, groups, membership, files and seeders. Every command is one method, picked from a table that also says whether it needs a login and whether it changes state. `download_file` issues peer tickets. |
| `state/state_snapshot.cpp` | `TrackerState::serialize` and `restore`: the saved text format. |
| `state/password` | PBKDF2 password hashing and checking. |

### 2.2 Client (`client/`)

The prompt and tracker connection sit at the top; `peer/` talks to other peers, `download/` runs downloads, `storage/` handles files on disk.

| File | Role |
| --- | --- |
| `main.cpp` | Entry point: `client <peer IP:PORT> <client.conf>`. |
| `client` | `Client`: the command prompt. Owns every other part and sends each command to the right one. |
| `command_line` | `CommandLine`: splits typed input (quotes, escapes) and accepts both `create user` and `create_user`. |
| `tracker_client` | `TrackerClient`: requests to the tracker, keeping the session ID. |
| `storage/shared_files` | `SharedFiles`: the files this client seeds, complete or partly downloaded. |
| `peer/peer_server` | `PeerServer`: answers other peers' bitmap and piece requests that carry a valid ticket. |
| `peer/peer_client` | `PeerClient`: asks a seeder for its bitmap or a piece and checks the piece hash. |
| `peer/peer_protocol` | The encrypted peer-to-peer message format, shared by both sides. |
| `peer/peer_stats` | `PeerStats`: per-peer successes, failures and speed for `show peers`. |
| `download/download` | `Download`: one download, from resume check to rarest-first parallel fetch to the final hash check; renews tickets before they expire. |
| `download/download_manager` | `DownloadManager`: starts, lists, measures and cancels downloads. |
| `storage/piece_file` | `PieceFile`: reads, writes and hashes a file one 512 KiB piece at a time. |
| `download/resume_manifest` | `ResumeManifest`: the `<dest>.resume` file that lets a download continue. |
| `storage/local_file.hpp` | `LocalFile`: a seeded file's path, metadata and available pieces. |

### 2.3 Shared code (`common/`)

`net/` is sockets and the secure tracker channel, `crypto/` wraps OpenSSL, `config/` reads config files and creates keys.

| File | Role |
| --- | --- |
| `net/net` | `Endpoint` (IPv4 address and port) and `Socket` (RAII socket with length-prefixed frames). |
| `net/tcp_server` | `TcpServer`: accepts connections and handles each one on its own thread. Used by the tracker and the peer server. |
| `crypto/crypto` | OpenSSL wrappers: random bytes, SHA-1, SHA-256, HMAC-SHA256, PBKDF2, AES-256-GCM, Ed25519, X25519. |
| `net/secure_channel` | `SecureChannel`: the client-to-tracker handshake and the sealed request and reply. |
| `file_metadata` | `FileMetadata`: a file's size and hashes, with validation. |
| `peer_ticket` | `PeerTicket` and `SeederAccess`: the tickets the tracker issues and seeders check. |
| `config/client_config` | `ClientConfig`: reads and writes `client.conf`. |
| `config/tracker_identity` | `TrackerIdentity`: creates and loads the tracker's signing key, and writes `client.conf`. |
| `encoding` | Hex, decimal parsing, split and join. |
| `net/freshness.hpp` | The five-minute timestamp window for handshakes and peer requests. |
| `crypto/openssl_ptr.hpp` | `std::unique_ptr` for OpenSSL objects. |

### 2.4 Tools (`tools/`)

`torrent_keygen <tracker IP:PORT> <keys-dir> <client.conf>` creates the tracker's signing key and the client config (see [SECURITY.md](SECURITY.md#3-keys-and-who-holds-them)).

### 2.5 Third-party code

| Library | Used for | How it arrives |
| --- | --- | --- |
| OpenSSL 3 | All cryptography | System package |

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
| `remove member <group> <user>` | Remove a member; they get no more tickets and their shares in the group are dropped | Group owner |
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
 client A                                   tracker
    │ 1. read file, SHA-1 each 512 KiB piece
    │    and the whole file
    │ 2. upload_file group name size hash      ──▶  checks membership, saves
    │    piece-hashes my-ip my-port my-peer-key
    │                                          ◀──  OK file shared
    │ 3. start serving pieces from the peer server
```

The peer key is a random 256-bit key the client makes when it starts. Only the tracker learns it; it is how the tracker issues tickets that this seeder will accept.

### 4.2 Download

```text
 client B                     tracker                        seeders A, C
    │ download_file group name ──▶ checks membership
    │ ◀── META size hash piece-hashes, and for each seeder:
    │     address / ticket / ticket key   (ticket valid 5 minutes)
    │
    │ BITMAP request (ticket + encrypted) ──────────────────────▶ each seeder
    │ ◀─────────────────────────────── which pieces each one has
    │
    │ sort missing pieces: rarest first (fewest holders), then by index
    │ start up to 8 workers; each takes the next piece:
    │      GET piece i (ticket + encrypted) ────────────────────▶ a holder
    │      ◀──────────────────────────────── piece bytes (encrypted)
    │      SHA-1 matches? ── no ─▶ try another holder (3 rounds, back-off)
    │            │ yes
    │      write piece, fsync, update resume manifest,
    │      start seeding this piece to others immediately
    │ a minute before tickets expire ─▶ download_file again for fresh ones
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
├── config/                 created by torrent_keygen (git-ignored):
│                           keys/ and client.conf
├── client/                 client program
│   ├── peer/               peer server, peer requests, peer stats
│   ├── download/           downloads and resume manifests
│   └── storage/            piece files and the list of seeded files
├── tracker/                tracker program: service, state file
│   └── state/              users, groups, files, passwords, saved format
├── common/                 shared code
│   ├── net/                sockets, TCP server, secure tracker channel
│   ├── crypto/             OpenSSL wrappers
│   └── config/             client.conf, tracker key
├── tools/keygen.cpp        key and certificate generator
├── tests/                  unit and integration tests (CTest)
├── PROJECT.md              this file
├── DESIGN.md               design
├── SECURITY.md             security design
├── TECHNICAL_REPORT.md     implementation notes and trade-offs
└── README.md               quick start
```

`config/` (keys and `client.conf`) and `data/` (tracker storage) are created at run time and ignored by git.

---

## 6. Build, run, test

### Build

Requirements: CMake 3.16+, a C++17 compiler and OpenSSL 3. On macOS with Homebrew, add `-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3` to the first command.

```sh
cmake -S . -B build
cmake --build build -j
```

### Run locally

```sh
# once: the tracker's key and client.conf
./build/torrent_keygen 127.0.0.1:6000 config/keys config/client.conf

# the tracker
./build/tracker 127.0.0.1:6000 config/keys data

# clients, each with its own peer address
./build/client 127.0.0.1:8101 config/client.conf
./build/client 127.0.0.1:8102 config/client.conf
```

Type `quit` in the tracker's terminal to stop it.

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
| `tracker_state_tests` | Tracker commands; access control (login, member-only, owner-only); removing members; ticket issue; lockout; saved-state round trip |
| `peer_access_tests` | The peer server accepts a valid ticket and gives one identical `60\|denied` to guessed keys, edited or expired tickets, garbage, and files it doesn't have |
| `tracker_integration_tests` | Tracker process: commands, crash and restart, no plaintext password on disk, plain-text, wrong-key and replay attacks |
| `client_integration_tests` | Full upload and encrypted multi-peer download, `show downloads`, retry after a seeder leaves, a member's ticket working and stopping after `remove member` |
| `peer_rejection_test` | A running client answers garbage and forged requests with the same `60\|denied` |

CI (`.github/workflows/ci.yml`) runs a release build and an AddressSanitizer/UBSan build on every push.

---

## 7. Limits and future work

- **One tracker:** if it is down, nobody can log in or start a download (transfers already running continue). Back up `data/`.
- **Revocation takes up to 5 minutes at seeders:** a removed member's tickets work until they expire.
- **Crashed seeders stay listed** until that user logs out, stops sharing or leaves the group. Downloads still succeed by retrying other peers.
- **SHA-1 for integrity** is kept for compatibility; SHA-256 would be the modern choice.

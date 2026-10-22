# Design

This document explains how Torrent Atlas works and which problem each part solves. For the project overview see [PROJECT.md](PROJECT.md); for security see [SECURITY.md](SECURITY.md).

---

## 1. Two separate planes

The system splits into two planes with very different needs.

```text
                    CONTROL PLANE (small, must be correct)
   ┌──────────────────────────────────────────────────────────────────┐
   │  users · password hashes · sessions · groups · members ·         │
   │  join requests · file metadata (size, hashes) · seeders          │
   │                                                                  │
   │                    tracker  ── tracker.state on disk              │
   └──────────────────────────────────────────────────────────────────┘
                 ▲ metadata and peer tickets (a few KB per request)
                 │
   ┌─────────────┴────────────────────────────────────────────────────┐
   │                    DATA PLANE (large, must be fast)               │
   │                                                                  │
   │    peer A ◀════ 512 KiB pieces ════▶ peer B ◀════▶ peer C         │
   └──────────────────────────────────────────────────────────────────┘
```

| | Control plane | Data plane |
| --- | --- | --- |
| Holds | Who exists, who is allowed, where files are | The file bytes |
| Size | Kilobytes | Up to gigabytes |
| What matters most | Correct access decisions; no acknowledged change lost | Throughput and integrity |
| Mechanism | One tracker that saves its state after every change | Direct parallel peer transfer |

**Why split them:** if file bytes went through the tracker, it would be the bandwidth bottleneck. Keeping the tracker to metadata keeps it small and fast, and lets file transfers scale with the number of peers.

---

## 2. The tracker

### 2.1 One process, one state

There is a single tracker. It holds a `TrackerState` in memory (users, password hashes, sessions, login lockouts, groups, members, join requests, files and seeders) and answers every client command from it.

```text
 client ── sealed "C\t<session>\t<command>" ──▶ TrackerService::handle
                                                  │
                                read-only command ├──▶ TrackerState::apply ──▶ reply
                                                  │
                          state-changing command  └──▶ lock ─▶ apply ─▶ save ─▶ reply
```

- **Reads** (`list_groups`, `list_files`, `download_file`, ...) run concurrently; `TrackerState` has its own lock.
- **Writes** (`create_user`, `login`, `upload_file`, `remove_member`, ...) run one at a time. Each one is applied and then the whole state is saved before the client gets its answer.

The command table in `TrackerState` marks which commands need a login and which change state, so `TrackerService` knows when to save.

### 2.2 Durable storage

```text
 data/
 └── tracker.state    one record per line, every name hex-encoded:
                      U <user> <pbkdf2 hash>      S <session> <user>
                      T <user> <failures> <locked until>
                      G <group> <owner>           M / R <group> <member / pending user>
                      F <group> <file> <size> <SHA-1> <piece hashes>
                      D <group> <file> <seeder> <ip> <port> <peer key>
```

Every save writes `tracker.state.tmp` (mode `0600`), fsyncs it and renames it over the old file, so a crash leaves either the old state or the new one, never a mix. On start the tracker loads the file; a missing file means a fresh tracker, and a corrupt one stops it rather than start empty.

Only the serialized state is ever written. Commands are never logged, so the passwords inside `create_user` and `login` never reach the disk; the state holds PBKDF2 hashes only (`tracker_integration_tests` scans the data directory for the typed passwords after signup, a failed login and a good login).

**Trade-off:** the whole state is rewritten on every change. That is simple and plenty fast for the kilobytes of metadata a class-sized deployment has. A much larger deployment would want an append-only journal or an embedded database.

### 2.3 What happens when it fails

| Failure | What happens | Data at risk |
| --- | --- | --- |
| Tracker crashes | Clients get `ERR tracker unavailable` until it restarts; peer transfers already under way keep going | None that was acknowledged |
| Tracker restarts | Loads `tracker.state`; sessions, groups and seeders are as they were | None |
| Disk lost | Everything is gone | All metadata; keep backups of `data/` |

`tracker_integration_tests` kills the tracker with `SIGKILL`, restarts it and checks that state and sessions survived.

### 2.4 `ApplyContext`

`TrackerState::apply(session, command, context)` never calls the random generator or the clock itself. `ApplyContext::fresh()` supplies the password salt, a new session ID and the current time. That keeps `TrackerState` easy to test: a test can pass a fixed time and check the exact ticket the tracker issues.

---

## 3. Clients and the tracker

`client.conf` holds the tracker's address and its Ed25519 public key. Each request opens a TCP connection, does the security handshake ([SECURITY.md](SECURITY.md#4-client-to-tracker-channel)), sends one sealed request and reads one sealed reply. This is simple and makes replay attacks impossible, at the cost of one extra round trip per command. Tracker commands are infrequent compared with piece transfers, so the cost is small.

---

## 4. The peer-to-peer data plane

### 4.1 Pieces

Files are cut into **512 KiB** pieces (the last may be shorter). The tracker stores the SHA-1 of each piece and of the whole file.

```text
 file (1.2 MiB)
 ┌──────────────┬──────────────┬───────┐
 │ piece 0      │ piece 1      │ p 2   │
 │ 512 KiB      │ 512 KiB      │ 205 K │
 │ sha1 = a3f…  │ sha1 = 91c…  │ 0d7…  │
 └──────────────┴──────────────┴───────┘
 full-file sha1 = 6be…
```

**What this solves:** pieces can come from different peers in parallel, a corrupt piece costs only 512 KiB to refetch, and progress can be saved piece by piece.

### 4.2 Who may ask a seeder: peer tickets

A seeder must only serve people the tracker currently lets into the group, and it must be possible to cut someone off. There is no long-lived file key to leak. Instead:

```text
 seeder A starts:       peer key kA = RAND_bytes(32), new every run
 A shares a file:       upload_file … A's address, kA ──▶ tracker   (sealed)

 member B:              download_file group file ──▶ tracker
                        tracker: B is a member? ──no──▶ ERR not a group member
                                                 yes
                        ticket = "<B>.<group>.<file>.<now + 300 s>"   (names hex)
                        key    = HMAC-SHA256(kA, ticket)
                        ◀── META … A's address / ticket / key        (sealed)

 B ──▶ A:               21 | ticket | AES-256-GCM(key, request)
 A:                     key' = HMAC-SHA256(kA, ticket); decrypt with key'
```

Only the tracker and A know `kA`, so only the tracker can make a ticket whose key A will accept. The ticket names the user, group, file and expiry, and any edit changes the key. B never holds anything that outlives five minutes or works at another seeder.

- **Revocation:** `remove_member` (owner) or `leave_group` ends membership. The tracker refuses that user new tickets at once and stops listing their own shares; tickets already issued die within five minutes.
- **Long downloads:** `Download` asks the tracker for fresh tickets a minute before the current ones expire. A user removed mid-download can't refresh, so the download stops.
- **No file-existence oracle:** the seeder checks the ticket and decrypts the request *before* it looks up the file, and answers every failure with the same `60|denied`. Someone without a valid ticket can't tell which files the peer has.

### 4.3 Choosing pieces: rarest first

```text
 holders per piece (from BITMAP replies):
   piece:     0   1   2   3   4   5
   holders:   3   1   2   3   1   2
 order:  1, 4, 2, 5, 0, 3     (fewest holders first, ties by index)
```

**What this solves:** a piece held by only one peer is the most at risk of disappearing. Fetching it first, and re-seeding it immediately, makes it available from more places.

### 4.4 Parallel workers

```text
 queue: [1][4][2][5][0][3]
          │  │  │
   W1 ◀───┘  │  │        up to 8 workers, never more than the number of peers
   W2 ◀──────┘  │        or of missing pieces
   W3 ◀─────────┘
 each worker:
   take next piece ─▶ ask a holder (holders rotated per piece to spread load)
        └─ fail or bad hash ─▶ next holder ─▶ after all: back-off, retry
           (3 rounds; back-off 150 ms × 2^round + jitter)
```

**What this solves:** downloads use many peers' upload bandwidth at once, and one slow or broken peer does not stall the transfer.

### 4.5 Partial seeding

When a download starts, the downloader registers with the tracker as a seeder of the file (with its own peer key), so other peers can find it from the beginning. Then, as soon as each piece is verified, it:

1. writes the piece and fsyncs,
2. marks it in the resume manifest, and
3. marks it available in its own peer server, so the next `BITMAP` request shows it.

```text
 time ─▶
 A (full) ──pieces──▶ B (has 0,1)
                       └──piece 0──▶ C       C fetches from B before B finishes
```

**What this solves:** popular files spread faster, and the original seeder's upload bandwidth is not the bottleneck.

### 4.6 Resume after a crash

```text
 bob.bin.part     the file being built (full size from the start)
 bob.bin.resume   P2PRESUME2 / group / name / size / hash / piece hashes /
                  verified-bitmap 0110100… / path of .part     (mode 0600)

 on resume:  for every piece marked verified ─▶ re-read and re-hash it
             mismatch ─▶ treat as missing
 finish:     full-file SHA-1 ─▶ rename .part to the final name, delete .resume
```

The manifest holds no keys; a resumed download gets fresh tickets from the tracker like any other.

**What this solves:** a crash or `cancel download` does not throw away finished work, and a manifest corrupted or edited on disk cannot inject bad data, because everything is re-verified.

---

## 5. End-to-end example

```text
 alice (seeder)              tracker                       bob (downloader)
     │ create_user, login ──▶ save
     │ create_group demo ──▶ save
     │                                       ◀── create_user, login, join_group demo
     │ accept_request demo bob ──▶ save
     │ upload_file demo song.mp3 ──▶ save (hashes, alice's address, alice's peer key)
     │                                       ◀── download_file demo song.mp3
     │                       bob is a member ─▶ META … alice / ticket / key
     │◀══════ BITMAP, GET piece 0..n (ticket + AES-GCM under its key) ═══════│
     │                                       bob verifies, writes, re-seeds
     │                       ◀── upload_file (bob is now a seeder too)
     │ remove_member demo bob ──▶ save
     │                                       ◀── download_file demo song.mp3
     │                       ERR not a group member ──▶ bob
     │                       bob's tickets expire within 5 minutes
```

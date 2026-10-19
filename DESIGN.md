# Distributed design

This document explains every distributed piece of Torrent Atlas: what it does, how it works, and which problem it solves. For the project overview see [PROJECT.md](PROJECT.md); for security see [SECURITY.md](SECURITY.md).

---

## 1. Two separate planes

The system splits into two planes with very different needs.

```text
                    CONTROL PLANE (small, must be correct)
   ┌──────────────────────────────────────────────────────────────────┐
   │  users · password hashes · sessions · groups · members ·         │
   │  join requests · file metadata (size, hashes, key) · seeders     │
   │                                                                  │
   │        tracker 1  ◀──Raft──▶  tracker 2  ◀──Raft──▶  tracker 3   │
   └──────────────────────────────────────────────────────────────────┘
                 ▲ metadata only (a few KB per request)
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
| What matters most | Every replica agrees; no acknowledged change is ever lost | Throughput and integrity |
| Mechanism | Raft consensus over 3 trackers | Direct parallel peer transfer |

**Why split them:** if file bytes went through the trackers, the trackers would be the bandwidth bottleneck and a single point of failure for data. Keeping trackers to metadata lets a small consensus cluster stay fast, and lets file transfers scale with the number of peers.

---

## 2. The tracker cluster

### 2.1 The problem it solves

One tracker is a single point of failure: if it dies, nobody can log in or find files, and if its disk dies, every account is gone. Adding copies raises a harder question: **how do several machines agree on the same state when any of them can crash, restart or be cut off at any moment?**

Simple approaches fail:

```text
 "Write to all, answer when done"     one slow or dead copy blocks every write
 "Write to one, copy later"           crash before the copy loses the write
 "Fixed primary + backups"            primary dies, writes stop until a human acts;
                                      a backup promoted by hand may be missing writes
```

Raft solves this. Each change is acknowledged only once a **majority** stores it, and a **new leader is elected automatically**. Election rules guarantee the new leader already has every acknowledged change.

### 2.2 Why three nodes, and why a majority

```text
  nodes   majority   failures tolerated
    1        1             0
    3        2             1        ◀── this project
    5        3             2
```

Any two majorities of three nodes share at least one node:

```text
   {1,2}   {2,3}   {1,3}      every pair overlaps
```

So if a write reached a majority, every later majority (including whichever one elects the next leader) contains at least one node that has the write. That overlap is what makes "acknowledged means never lost" true.

Even cluster sizes add no tolerance: 4 nodes still tolerate only 1 failure (majority is 3), so `cluster.conf` must list an odd number of trackers.

### 2.3 Roles and terms

Every tracker is in exactly one role:

```text
              timeout, no heartbeat from a leader
   ┌──────────┐ ───────────────────────────────▶ ┌───────────┐
   │ FOLLOWER │                                  │ CANDIDATE │
   └──────────┘ ◀─────────────────────────────── └───────────┘
        ▲        sees a higher term / a leader        │
        │                                             │ wins votes from a majority
        │        sees a higher term                   ▼
        └──────────────────────────────────────  ┌──────────┐
                                                 │  LEADER  │
                                                 └──────────┘
```

- **Term:** a number that only goes up. Each election starts a new term, and at most one leader can win in a term. Any message from a higher term makes a node step down to follower.
- **Heartbeat:** the leader sends one to each follower every **100 ms**.
- **Election timeout:** a follower that hears nothing for a random **400 to 800 ms** becomes a candidate and asks for votes. The randomness keeps two nodes from repeatedly splitting the vote.
- **Vote rule:** a node votes for at most one candidate per term, and only for one whose log is at least as up to date as its own. This is what keeps a node with missing writes from becoming leader.

### 2.4 How a write flows

```text
 client          tracker 2 (follower)   tracker 1 (leader)     tracker 3 (follower)
   │  create_group demo  │                      │                      │
   │────────────────────▶│                      │                      │
   │◀── REDIRECT t1 ─────│                      │                      │
   │                                            │                      │
   │  create_group demo                         │                      │
   │───────────────────────────────────────────▶│                      │
   │                       1. build log entry:  │                      │
   │                          session, salt,    │                      │
   │                          new session id,   │                      │
   │                          time, command     │                      │
   │                       2. append + fsync    │                      │
   │                                            │── AppendEntries ────▶│
   │                    ◀────── AppendEntries ──│                      │
   │                          3. followers append + fsync, reply OK    │
   │                    ─────────────────────▶  │ ◀────────────────────│
   │                       4. 2 of 3 have it:   │                      │
   │                          COMMITTED         │                      │
   │                       5. apply to state    │                      │
   │◀── OK group created ───────────────────────│                      │
   │                       6. followers apply on the next heartbeat    │
```

1. **Redirect:** clients may contact any tracker. A follower answers `REDIRECT <leader address>`, and the client remembers the leader for next time.
2. **The leader fixes all randomness** (password salt, new session ID, current time) inside the log entry. This matters because each replica *re-runs* the command: if each one picked its own salt or session ID, the replicas would end up with different state. With everything in the entry, every replica computes exactly the same result (see 2.6).
3. **fsync before acknowledging:** each node writes the entry to `raft.log` and syncs it to disk before telling the leader it has it, so "stored" means it survives power loss.
4. **Commit on a majority:** the leader needs one follower plus itself. A slow or dead third node does not hold up writes.
5. **Answer after apply:** the client's reply is the result of applying the committed entry, such as `OK group created` or `ERR group already exists`.

### 2.5 How a read flows

```text
 client ── list_files demo ──▶ leader ── reads its own state ──▶ answer
```

Reads are not logged; the leader answers from memory. A newly elected leader first applies every entry committed before its election, and until then answers reads with `ERR leader catching up; retry`, which the client retries. So a client always sees its own earlier writes (read-your-writes), even right after a failover or a full restart.

**Edge case:** if the leader is cut off from both followers, it keeps answering reads until its lease expires (20 × heartbeat ≈ **2 s**), then steps down. Reads in that window may miss writes that a new leader accepted on the other side. Its own writes cannot commit, because it has no majority.

### 2.6 Determinism: why the state machine takes an `ApplyContext`

```text
 WITHOUT a fixed context                   WITH ApplyContext in the log entry
 ───────────────────────                   ──────────────────────────────────
 t1: create_user → salt A → hash A         entry: salt S, session N, time T
 t2: create_user → salt B → hash B         t1, t2, t3 all → hash(S), session N
 t3: login       → session X               state identical everywhere ✔
     login on t2 → session Y   ✘ diverged
```

`TrackerState::apply(session, command, context)` never calls the random generator or the clock directly. On the cluster, the leader builds the context once with `ApplyContext::fresh()` and stores it in the entry. Failed logins are logged too, so the five-strike lockout counter is the same on every node and survives failover. A test (`tracker_state_tests`) applies the same log to two states and checks they serialize to identical bytes.

### 2.7 Durable storage

Each tracker owns a data directory:

```text
 data/node1/
 ├── raft.log       [start index] then [index][length][entry] records
 ├── state.bin      current term and the vote cast in it
 ├── config.bin     cluster membership
 └── snapshot.bin   snapshot metadata + full serialized tracker state
```

| File | Why it must survive a crash |
| --- | --- |
| `raft.log` | A node that acknowledged an entry must still have it after a restart, or the majority guarantee breaks. |
| `state.bin` | A node that forgot its vote could vote twice in one term and allow two leaders. |
| `config.bin` | The node must remember who is in the cluster. |
| `snapshot.bin` | It lets the log be trimmed, and a restart begins from it. |

Every whole-file write goes to a temporary file, is fsynced, and is renamed over the old file, so a crash leaves either the old version or the new one, never a mix. Appends to `raft.log` are fsynced one by one. A torn final record is ignored on load, and the leader then re-sends that entry.

### 2.8 Snapshots and log compaction

Without compaction the log would grow forever, and a new node would have to replay every command ever run.

```text
 log:   [1][2][3] ... [1000][1001][1002] ...
                        ▲
                snapshot at 1000 = full state after entry 1000
 after compaction:  snapshot@1000 + [1001][1002] ...
```

- A snapshot is taken every **1000** committed entries, from the state at exactly that point, and saved to `snapshot.bin`.
- Older entries are dropped from `raft.log`.
- A follower too far behind to catch up from the log receives the snapshot in **1 MiB chunks**, installs it, then receives the newer entries. Chunking avoids any single message hitting the 16 MiB frame limit.

### 2.9 What happens when things fail

```text
 normal          leader crash          follower crash        2 of 3 down
 ┌──┐┌──┐┌──┐    ┌──┐┌──┐┌──┐          ┌──┐┌──┐┌──┐          ┌──┐┌──┐┌──┐
 │L ││F ││F │    │✖ ││F ││F │          │L ││F ││✖ │          │✖ ││F ││✖ │
 └──┘└──┘└──┘    └──┘└──┘└──┘          └──┘└──┘└──┘          └──┘└──┘└──┘
 reads ✔          ~0.4-0.8 s later:     reads ✔               no leader can be
 writes ✔         a follower wins       writes ✔ (L + F       elected; writes
                  the vote, becomes L;  is a majority)        refused, nothing
                  reads ✔ writes ✔                            half-applied
```

| Failure | What happens | Data at risk |
| --- | --- | --- |
| Leader crashes | New leader in about one election timeout; clients follow `REDIRECT` | None that was acknowledged |
| Follower crashes | Unnoticed by clients | None |
| Crashed node restarts | Loads snapshot, replays log, catches up from the leader | None |
| 2 of 3 down | Writes refused (`ERR no leader` or `ERR write not committed`) | None; the cluster becomes unavailable rather than unsafe |
| All 3 restart | Each rebuilds from disk, elects a leader | None |
| Network partition | Only the majority side elects a leader and commits; the minority side's old leader steps down after about 2 s | None that was acknowledged |
| Disk lost on one node | Treat it as a fresh node; it catches up by snapshot | None, while the other two have it |

These are exercised by `tracker_integration_tests`, which kills real processes with `SIGKILL`.

### 2.10 Why NuRaft instead of hand-written Raft

Raft is small on paper, but correct implementations must handle log conflicts, term races, snapshot transfer and joint membership. NuRaft (eBay) is a production C++ library that does all of that. This project supplies the parts that are specific to it:

```text
 ┌─────────────────────── NuRaft ───────────────────────┐
 │ elections · heartbeats · AppendEntries · commit index │
 │ log conflict resolution · snapshot transfer · TLS RPC │
 └───────▲───────────────▲────────────────▲──────────────┘
         │ state_machine │ log_store      │ state_mgr
 ┌───────┴──────┐ ┌──────┴───────┐ ┌──────┴────────┐
 │TrackerState- │ │ FileLogStore │ │FileStateManager│   ◀── this project
 │Machine       │ │ (raft.log)   │ │(state, config) │
 └──────────────┘ └──────────────┘ └────────────────┘
```

---

## 3. Clients and the cluster

### 3.1 Finding the leader

```text
 client.conf: t1, t2, t3, <cluster public key>

 request ─▶ last known leader ──answer────────────────────────▶ done
                │
                ├─ REDIRECT tX ─▶ remember tX, retry there
                ├─ no connection ─▶ try the next tracker
                └─ "no leader yet" / "not committed" ─▶ wait 250 ms, retry
                   (up to 12 attempts, which covers an election)
```

**What this solves:** there is no load balancer to become a single point of failure, and clients ride through a leader change without user action.

### 3.2 One connection per request

Each request opens a TCP connection, does the security handshake ([SECURITY.md](SECURITY.md#4-client-to-tracker-channel)), sends one sealed request and reads one sealed reply. This is simple and makes replay attacks impossible, at the cost of one extra round trip per command. Tracker commands are infrequent compared with piece transfers, so the cost is small.

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

### 4.2 Choosing pieces: rarest first

```text
 holders per piece (from BITMAP replies):
   piece:     0   1   2   3   4   5
   holders:   3   1   2   3   1   2
 order:  1, 4, 2, 5, 0, 3     (fewest holders first, ties by index)
```

**What this solves:** a piece held by only one peer is the most at risk of disappearing. Fetching it first, and re-seeding it immediately, makes it available from more places.

### 4.3 Parallel workers

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

### 4.4 Partial seeding

When a download starts, the downloader registers with the tracker as a seeder of the file, so other peers can find it from the beginning. Then, as soon as each piece is verified, it:

1. writes the piece and fsyncs,
2. marks it in the resume manifest, and
3. marks it available in its own peer server, so the next `BITMAP` request shows it.

```text
 time ─▶
 A (full) ──pieces──▶ B (has 0,1)
                       └──piece 0──▶ C       C fetches from B before B finishes
```

**What this solves:** popular files spread faster, and the original seeder's upload bandwidth is not the bottleneck.

### 4.5 Resume after a crash

```text
 bob.bin.part     the file being built (full size from the start)
 bob.bin.resume   P2PRESUME1 / group / name / size / hash / key / piece hashes /
                  verified-bitmap 0110100… / path of .part     (mode 0600)

 on resume:  for every piece marked verified ─▶ re-read and re-hash it
             mismatch ─▶ treat as missing
 finish:     full-file SHA-1 ─▶ rename .part to the final name, delete .resume
```

**What this solves:** a crash or `cancel download` does not throw away finished work, and a manifest corrupted or edited on disk cannot inject bad data, because everything is re-verified.

---

## 5. End-to-end example

```text
 alice (seeder)        tracker cluster (L = leader)          bob (downloader)
     │ create_user, login ──▶ L: log, commit 2/3
     │ create_group demo ──▶ L: log, commit
     │                                       ◀── create_user, login, join_group demo
     │ accept_request demo bob ──▶ L: log, commit
     │ upload_file demo song.mp3 ──▶ L: log (hashes, capability, alice's address)
     │                                       ◀── download_file demo song.mp3
     │                          L: bob is a member ─▶ META … capability … alice
     │◀══════════ BITMAP, GET piece 0..n (AES-GCM under capability) ═════════│
     │                                       bob verifies, writes, re-seeds
     │                          ◀── upload_file (bob is now a seeder too)
   ✖ L crashes
                                follower wins election (~0.5 s)
                                       ◀── list_files demo  (REDIRECT, then answer)
                                           song.mp3 is still there ✔
```

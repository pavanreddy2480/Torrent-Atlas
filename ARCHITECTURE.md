# Architecture and protocol

## Components

Three trackers form a NuRaft cluster; any number of clients connect to it. Trackers hold metadata only. File bytes move directly between clients.

```text
Write:  client -> any tracker -> REDIRECT -> leader -> Raft log, majority stored -> response
Read:   client -> leader -> response
Pieces: client <------------- AES-256-GCM -------------> client
```

The supported process forms are:

```text
torrent_keygen <cluster.conf> <keys-dir> <client.conf>
tracker <cluster.conf> <node-id> <keys-dir> <data-dir>
client <peer-ip:port> <client.conf>
```

`cluster.conf` has one line per tracker, `<id> <client IP:PORT> <raft IP:PORT>`, and must list an odd number of trackers (3 or more). `client.conf` lists every tracker's client address and, on its last line, the cluster's Ed25519 public key.

## Raft replication

The tracker state (users, password hashes, sessions, login lockouts, groups, membership requests, files, seeders) is a deterministic state machine driven by the Raft log (`tracker/raft_tracker.hpp`).

- **Commands that change state** (`create_user`, `login`, `logout`, `create_group`, `join_group`, `leave_group`, `accept_request`, `upload_file`, `stop_share`) become log entries:

  ```text
  <session>\t<salt hex>\t<new session id>\t<unix seconds>\t<command>
  ```

  The leader picks the password salt, the new session ID and the current time once, so every replica applies the entry the same way. The leader answers the client with the result of applying the entry, after NuRaft reports it committed on a majority. Failed commands such as a wrong password are logged too, so the login lockout is the same on every node.
- **Reads** run on the leader's state and are not logged.
- **Followers** return `REDIRECT <leader client address>\t<session>`. With no leader yet, a tracker returns `ERR no leader elected yet; retry`. If a write cannot commit in 3 s (for example, no majority), the leader returns `ERR write not committed by a majority; retry`.
- **Timing:** heartbeat 100 ms, election timeout 400 to 800 ms.
- **Snapshots:** taken every 1000 entries; older entries are compacted. A lagging follower receives the snapshot in 1 MiB chunks, then the rest of the log.

### Storage (`tracker/raft_storage.hpp`)

Each tracker's data directory holds:

| File | Contents |
| --- | --- |
| `raft.log` | Every log entry; appends are fsynced, and truncation or compaction rewrites the file atomically |
| `state.bin` | Current term and vote |
| `config.bin` | Cluster membership |
| `snapshot.bin` | Latest snapshot metadata and serialized tracker state |

On restart, a tracker loads its snapshot, then NuRaft replays newer committed entries.

## Client protocol

Every message uses a 4-byte big-endian payload length followed by that many bytes. Payloads above 16 MiB are rejected. Each client connection is one signed X25519 handshake followed by one request and one reply, both AES-256-GCM sealed (see [SECURITY.md](SECURITY.md)). Inside the seal:

```text
C\t<session>\t<command>
<response-text>\t<session>
```

The client tries its last known leader first, follows `REDIRECT`, skips trackers that don't answer, and waits briefly while an election is in progress.

## Tracker-to-tracker protocol

This is NuRaft's own RPC protocol over TCP, wrapped in TLS 1.3 with mutual certificate authentication. Both sides must present a certificate signed by the cluster CA whose subject is `CN=torrent-node-<id>`.

## Peer protocol

The tracker returns file size, full SHA-1, a 256-bit capability, piece SHA-1 values, and sorted peer endpoints. The client validates all lengths, hashes, piece counts, and endpoints before allocation.

Peer messages use the same outer frame. Inside it, AES-256-GCM protects the operation and response. The authenticated data binds protocol direction, group, file, and request nonce so ciphertext cannot be moved to another context.

A downloader requests peer bitmaps, counts availability, and sorts missing pieces by `(availability, piece-index)`. Up to eight workers reserve different pieces. A failed or corrupt response is recorded factually and the worker tries another peer. There are no duplicate endgame requests, trust scores, or blacklist rules.

After a piece passes SHA-1 it is written, fsynced, recorded in the resume manifest, and exposed for partial seeding. On resume, every claimed piece is re-read and re-hashed. After all pieces complete, the full file is hashed before the `.part` file is renamed into place.

## Failure model

- **Leader crash:** a follower times out, wins a vote from the other survivor, and becomes leader. Only a node whose log has every committed entry can win, so no acknowledged write is lost.
- **Follower crash:** writes continue with the leader plus the other follower, which is still a majority. On restart, the follower catches up from the leader's log, or from a snapshot if the log has been compacted.
- **Two trackers down:** no majority, so no writes commit. The survivor does not become leader and does not serve reads.
- **All trackers restarted:** state is rebuilt from each node's snapshot and log on disk.
- **Network partition:** only the side with a majority can elect a leader and commit. An isolated old leader steps down when its lease expires (about 2 s). Until then it may still answer reads, but its writes cannot commit.
- **Torn writes:** an incomplete final record in `raft.log` is ignored on load; Raft then re-sends that entry from the leader.

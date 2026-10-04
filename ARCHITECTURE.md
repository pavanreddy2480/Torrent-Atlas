# Architecture and protocol

## Components

The system has one load balancer, three trackers, and any number of clients. Tracker 1 is the write server; trackers 2 and 3 are read servers. The LB and trackers hold metadata only. File bytes move directly between clients.

```text
Write:  client -> LB -> write server -> sync to both read servers -> response
Read:   client -> LB -> an in-sync read server -> response
Pieces: client <-------------- encrypted --------------> client
```

The supported process forms are:

```text
torrent_keygen <config-dir>                  # creates cluster.key, lb_identity.key, client.conf key
tracker <three-endpoint-config> <cluster.key> <1|2|3>   # 1 = write server, 2-3 = read servers
tracker_lb <listen-write-read-read-config> <cluster.key> <lb_identity.key>
client <peer-ip:port> <client.conf>          # LB IP:PORT + LB public key
```

## Routing

The LB classifies each request by its command. `create_user`, `login`, `logout`, `create_group`, `join_group`, `leave_group`, `accept_request`, `upload_file` and `stop_share` are writes and go only to the write server. Everything else is a read.

For a read, the LB asks all three trackers for their status:

```text
X\t0\tSTATUS
STATUS\t<primary|replica>\t<sequence>\t<READY|RECOVERING>
```

If the write server is ready, the read goes round-robin to a read server whose sequence equals the write server's, or to the write server if neither read server is in sync. If the write server is unreachable, the read goes to the read server with the highest sequence. With no tracker reachable the LB answers `ERR tracker service unavailable`; with the write server unreachable a write gets `ERR write server unavailable`.

The LB never logs request payloads, so passwords are not written to its logs.

## Tracker protocol

Every application message uses a 4-byte big-endian payload length followed by that many bytes. Payloads above 16 MiB are rejected.

The messages below are what travels inside two secure wrappers (details in [SECURITY.md](SECURITY.md)):

- **Client to LB:** a signed X25519 handshake, then the `C` request and its reply sealed with AES-256-GCM under the session key.
- **LB to tracker and tracker to tracker:** every frame is `<unix-seconds>\t<AES-256-GCM nonce, tag, ciphertext>` under the cluster key, with the timestamp as authenticated data. Frames older than 30 s or that fail to decrypt are refused. The LB only accepts `C` requests from clients, so clients can never send `S`, `P` or `X` frames into the cluster.

Client request and response:

```text
C\t<session>\t<command>
<response-text>\t<session>
```

Read servers answer client writes with `ERR read-only server; send writes to the write server`.

Replication, from the write server to each read server, holding the write server's mutation lock so entries are strictly ordered:

```text
S\t<sequence>\t<session>\t<command>
APPLIED | DUPLICATE | RESYNC
```

A read server applies only `applied + 1`. Older sequences are `DUPLICATE`. A gap, or an entry that fails against local state, is `RESYNC`, and the write server immediately pushes a full snapshot:

```text
P\t<sequence>\n<state>
APPLIED
```

Snapshot read, used by a restarting write server:

```text
X\t0\tSNAPSHOT
SNAPSHOT\t<sequence>\n<state>
```

## Peer protocol

The tracker returns file size, full SHA-1, a 256-bit capability, piece SHA-1 values, and sorted peer endpoints. The client validates all lengths, hashes, piece counts, and endpoints before allocation.

Peer messages use the same outer frame. Inside it, AES-256-GCM protects the operation and response. The authenticated data binds protocol direction, group, file, and request nonce so ciphertext cannot be moved to another context.

A downloader requests peer bitmaps, counts availability, and sorts missing pieces by `(availability, piece-index)`. Up to eight workers reserve different pieces. A failed or corrupt response is recorded factually and the worker tries another peer. There are no duplicate endgame requests, trust scores, or blacklist rules.

After a piece passes SHA-1 it is written, fsynced, recorded in the resume manifest, and exposed for partial seeding. On resume, every claimed piece is re-read and re-hashed. After all pieces complete, the full file is hashed before the `.part` file is renamed into place.

## Failure model

- **Read server down.** The write server marks it out of sync and stops sending to it. Writes and reads continue on the other two nodes. A background loop checks both read servers every 250 ms and pushes a snapshot to any that is reachable but behind, so a restarted read server rejoins on its own.
- **Write server down.** Reads continue from the most advanced read server. Writes fail with `ERR write server unavailable`. There is no election.
- **Write server restart.** It answers `ERR write server recovering` until a read server responds, then copies the most advanced read server's snapshot and sequence. Read servers at that sequence are marked in sync; others are caught up by snapshot.
- **Data loss window.** If the write server restarts while the only reachable read server is behind, writes that only the other read server had are lost when that server is resynced.
- **All trackers down.** State is in memory only, so metadata is lost.
- The single LB is not replicated.

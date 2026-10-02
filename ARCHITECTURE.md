# Architecture and protocol

## Components

The system has one load balancer, two trackers, and any number of clients. The LB and trackers hold metadata only. File bytes move directly between clients.

```text
Client command -> LB -> owning tracker -> ordered replication -> response
Download metadata <- LB <- tracker
Encrypted pieces: client <---------------------------------> client
```

The supported process forms are:

```text
tracker <two-endpoint-config> <1|2>
tracker_lb <listen-and-two-backends-config>
client <peer-ip:port> <one-LB-endpoint-config> [--tui]
```

## Routing

The LB applies 64-bit FNV-1a to the user ID for `create_user` and `login`, and to the group ID for group/file commands. Commands without an aggregate key use the tracker tag in the high byte of the session ID. This gives each aggregate one normal owner while replicated sessions let group ownership differ from account ownership.

All state-changing requests pass through one LB mutation mutex. Read requests do not take that mutex. The LB never logs request payloads, so passwords are not written to its logs.

Before routing, the LB queries both trackers:

```text
X\t0\tSTATUS
STATUS\t<origin-1-seq>\t<origin-2-seq>\t<READY|DEGRADED>
```

If both ready vectors match, the normal owner is used. If only one tracker is ready, or one vector component-wise dominates the other, the current replica is used. Incomparable vectors and two unavailable/degraded backends return `ERR tracker service unavailable\t<session>`.

## Tracker protocol

Every application message uses a 4-byte big-endian payload length followed by that many bytes. Payloads above 16 MiB are rejected.

Client request and response:

```text
C\t<session>\t<command>
<response-text>\t<session>
```

Replication:

```text
S\t<origin>\t<sequence>\t<session>\t<command>
APPLIED | DUPLICATE | QUEUED | DEGRADED
```

Each tracker stores an applied sequence for both origins. `sequence <= applied` is a duplicate. A sequence above `applied + 1` is queued. Applying the missing sequence drains the contiguous queued suffix. A replay conflict advances past the poison item, marks the replica degraded, and prevents the FIFO from blocking forever.

Snapshot:

```text
X\t0\tSNAPSHOT
SNAPSHOT\t<origin-1-seq>\t<origin-2-seq>\t<READY|DEGRADED>\n<state>
```

A restarting tracker accepts only a ready, structurally valid snapshot. It restores the state and applied vector together. The surviving tracker may subsequently redeliver queued mutations; sequence deduplication makes that safe.

## Peer protocol

The tracker returns file size, full SHA-1, a 256-bit capability, piece SHA-1 values, and sorted peer endpoints. The client validates all lengths, hashes, piece counts, and endpoints before allocation.

Peer messages use the same outer frame. Inside it, AES-256-GCM protects the operation and response. The authenticated data binds protocol direction, group, file, and request nonce so ciphertext cannot be moved to another context.

A downloader requests peer bitmaps, counts availability, and sorts missing pieces by `(availability, piece-index)`. Up to eight workers reserve different pieces. A failed or corrupt response is recorded factually and the worker tries another peer. There are no duplicate endgame requests, trust scores, or blacklist rules.

After a piece passes SHA-1 it is written, fsynced, recorded in the resume manifest, and exposed for partial seeding. On resume, every claimed piece is re-read and re-hashed. After all pieces complete, the full file is hashed before the `.part` file is renamed into place.

## Failure model

- A failed replication attempt is retained in an origin-ordered in-memory retry queue.
- The LB can keep using a surviving tracker and will not send traffic back to a stale owner.
- A restart obtains a sequence-aware snapshot from the survivor.
- Two tracker failures lose metadata because persistence is intentionally out of scope.
- The single LB is not replicated.
- The model assumes one LB serializes client mutations; it is not Byzantine fault tolerant or a consensus protocol.

# Proposal: distributed tracker architecture

Status: draft for review. Nothing here is implemented yet.

## Where we are today

```text
clients ──> 1 load balancer ──> tracker 1 <──ordered replication──> tracker 2
peer <──────────── AES-GCM piece traffic ────────────> peer
```

The weak points, all documented in `ARCHITECTURE.md`:

- **Single load balancer.** It also serializes every mutation behind one mutex, so it is both a single point of failure and the write bottleneck.
- **Exactly two trackers.** Ownership is FNV-1a over two nodes, and the STATUS/SNAPSHOT logic compares a two-element applied vector. It does not generalise to N.
- **No consensus.** Primary/replica with retry queues. Incomparable vectors mean "service unavailable"; a replay conflict degrades a node until restart.
- **No persistence.** Losing both trackers loses all users, groups and file metadata.
- **Stale peer lists.** A peer that dies stays listed until `stop_share` or `logout`; downloaders find out by timing out.
- **Sessions are tracker-local state.** The session tag in the high byte routes requests to a specific tracker, coupling auth to placement.

The peer-to-peer data plane (framed TCP, AES-256-GCM, SHA-1 per piece, rarest-first, resumable `.part` files) is already decentralised and is kept as is.

## Proposed shape

```text
                 ┌────────────── tracker cluster (3 or 5 nodes) ──────────────┐
clients ──any──> │  node A (Raft leader)   node B (follower)   node C (follower) │
 (seed list)     │  WAL + snapshots on disk on every node                      │
                 └─────────────────────────────────────────────────────────────┘
                      ▲ announce + TTL lease (heartbeat every 30s)
peer <── encrypted pieces ──> peer <── peer exchange (PEX) ──> peer
```

### 1. Replace primary/replica with a Raft-replicated state machine

- The existing tracker state (users, groups, membership requests, file metadata, sharers) becomes a deterministic state machine. `tracker_common.hpp` already applies commands as text, so each client mutation becomes one Raft log entry.
- 3 nodes tolerate 1 failure, 5 tolerate 2. Writes commit on a majority; there is no "incomparable vector" state and no manual degraded mode.
- Reads: leader reads with a lease (linearizable), or follower reads for `list_files` / `list_groups` where slightly stale data is fine.
- Persistence: append-only WAL plus periodic snapshots. A restarted node replays its log or installs a snapshot from the leader. This fixes the "two failures lose everything" gap.
- Implementation: hand-written Raft in C++17 over the existing frame format (it is ~1.5k lines and keeps the project dependency-light), or vendor a library such as NuRaft. Recommendation: hand-written, because the repo is explicitly interview-sized and the protocol should be visible.

### 2. Remove the load balancer as a required hop

- Clients get a seed list of tracker endpoints (`config/client.conf` gains multiple lines) instead of one LB address.
- Any node accepts a request. Followers reply `REDIRECT <leader>` for writes; the client caches the leader and retries on the next seed if a node is down.
- `tracker_lb` can stay as an optional stateless proxy for demos, but it no longer holds the mutation mutex. Ordering comes from the Raft log.

### 3. Stateless, signed sessions

- `login` returns a token `user|expiry|nonce` signed with HMAC-SHA256 under a cluster key (OpenSSL is already linked). Any node verifies it without a lookup.
- `logout` writes a revocation entry to the Raft log so it survives failover.
- The tracker tag in the session high byte goes away.

### 4. Peer liveness via leases

- `upload_file` and a new `announce <group> <file>` register the sharer with a TTL (for example 90 s). The client already runs a peer server thread; it sends a heartbeat every 30 s.
- Expired sharers are dropped from `download_file` responses. Lease expiry is applied by the leader as a log entry so all replicas agree.

### 5. Peer exchange (optional, phase 3)

- Peers that are already connected share the endpoints they know for the same `(group, file)`, authenticated under the same file capability key. Downloads keep going during a tracker outage once the swarm is found.
- A full Kademlia DHT is deliberately out of scope: groups are private and access-controlled, so a public DHT would conflict with the membership model.

### 6. Scaling past one Raft group (only if needed)

Shard groups across several Raft groups with consistent hashing on `group_id`, with a small metadata group mapping shards to members. At the current project size one Raft group is enough; this is noted only so the design does not block it.

## What changes in the code

| Area | Change |
| --- | --- |
| `tracker/tracker_common.hpp` | Split into state machine, Raft module, and network server. Replication (`S\t...`), STATUS and SNAPSHOT messages are replaced by Raft RPCs (`RequestVote`, `AppendEntries`, `InstallSnapshot`). |
| `tracker/tracker_lb.cpp` | Becomes optional, or is removed. |
| `common/protocol.hpp` | Adds the Raft RPC frames, `REDIRECT`, signed-token encoding. Outer frame stays the same. |
| `client/` | Seed-list connection with leader caching; heartbeat thread; optional PEX handler on the peer server. Piece transfer code is unchanged. |
| `config/` | `trackers.conf` lists N nodes with IDs; `client.conf` lists seeds. |
| `tests/` | New: Raft election and log-matching unit tests, a 3-node integration test that kills the leader mid-upload, a lease-expiry test. Existing LB tests are retired with the LB. |

## Phased plan

1. **Raft core + persistence** with 3 nodes, LB still in front. Proves consensus without touching the client.
2. **Seed-list clients, redirects, signed sessions**; LB becomes optional.
3. **Peer leases and heartbeats**, then PEX.
4. Docs, failure-injection demo script, and updated `ARCHITECTURE.md`.

## Decisions needed

1. **Consensus:** Raft (recommended) or keep primary/replica and just generalise it to N nodes.
2. **Raft implementation:** hand-written (recommended for an interview project) or a library such as NuRaft.
3. **Load balancer:** drop it in phase 2 (recommended) or keep it as an optional proxy.
4. **PEX:** include in scope or defer.

# Security

Everything here uses OpenSSL's built-in primitives (already a dependency) and NuRaft's TLS support. There is no hand-rolled cryptography.

## The three links

| Link | Protection |
| --- | --- |
| Client to tracker | Signed X25519 handshake, then AES-256-GCM under a fresh per-connection session key. |
| Tracker to tracker (Raft) | TLS 1.3 with mutual certificate authentication against the cluster CA. |
| Peer to peer | AES-256-GCM under the file's 256-bit capability, plus a timestamp. |

## Keys

`torrent_keygen <cluster.conf> <keys-dir> <client.conf>` creates:

- `ca.crt` and `ca.key`: the cluster's certificate authority (P-256). Keep `ca.key` offline after setup; it is only needed to issue certificates.
- `node<id>.crt` and `node<id>.key`: each tracker's TLS certificate, `CN=torrent-node-<id>`, signed by the CA. Each tracker needs only its own key.
- `tracker_identity.key`: the Ed25519 key trackers use to sign client handshakes. Every tracker has a copy, so whichever one is leader can prove it belongs to the cluster.
- `client.conf`: the tracker addresses and the matching Ed25519 public key. Clients trust only this key (pinning).

Private keys are written with mode `0600`. The repository ignores `config/keys/` and `data/`.

## Client to tracker handshake

One round trip at the start of every connection:

1. **Client hello:** `HELLO | client X25519 public key | 16-byte nonce | timestamp`. The key pair is new for this connection.
2. **Tracker hello:** `HELLO | tracker X25519 public key | 16-byte nonce | timestamp | signature`. The signature is Ed25519 over both hellos, made with `tracker_identity.key`.
3. **Check:** the client verifies the signature against the pinned public key and disconnects on failure.
4. **Session key:** both sides compute `session key = SHA-256(X25519 shared secret || both hellos)`.
5. **Request and reply:** both are AES-256-GCM under the session key, labelled `client->tracker` and `tracker->client`. A request that decrypts proves the client derived the same key.

The account password travels only inside this channel. It is checked against a PBKDF2 hash that is replicated through Raft.

**What this gives:**

- **Confidentiality:** passwords, session IDs and file capabilities never cross the network in plain text.
- **Server authentication:** only a holder of `tracker_identity.key` can complete the handshake.
- **Client authentication:** the account password, sent inside the channel.
- **Replay protection:** both sides contribute fresh keys and nonces, so a recorded request replayed on a new connection does not decrypt. This needs no synchronized clocks.
- **Forward secrecy:** X25519 keys are discarded after each connection. A later leak of `tracker_identity.key` does not decrypt recorded traffic; it only allows impersonation from then on.

## Tracker to tracker

NuRaft's Raft RPCs (votes, heartbeats, log entries, snapshots) run over TLS 1.3. Both ends must present a certificate chained to the cluster CA, with a subject of `CN=torrent-cluster-ca` or `CN=torrent-node-<id>`. A process without a cluster certificate can't connect, so it can't:

- read replicated password hashes or sessions;
- vote in or disrupt elections;
- inject or rewrite log entries or snapshots.

Each node has its own private key. One stolen node key does not reveal the others, and removing that node means issuing new certificates.

## Peer traffic

The tracker gives group members a file's random 256-bit capability over the encrypted client channel. Peers use it as an AES-256-GCM key:

- **Opcode 21, request:** the group and file name are authenticated data. The operation, the piece index and a timestamp are encrypted. Seeders reject requests more than 5 minutes old (`60|stale`).
- **Opcode 30, response:** the bitmap or piece, authenticated against the original request and its nonce.
- **Opcode 60, rejection:** a short error with no file data.

## Other protections

- **Randomness:** `RAND_bytes` generates every key, nonce, salt and session ID. On the cluster, the leader generates them once per log entry so all replicas agree.
- **Password storage:** PBKDF2-HMAC-SHA256 with a random salt and 20,000 iterations, compared in constant time.
- **Login lockout:** five failed logins lock the account for 30 s. The lockout is replicated, so it survives failover.
- **SHA-1:** used only for piece and file integrity checks.
- **Resume manifests:** they contain capabilities, so they are written with mode `0600`.
- **Data directories:** trackers create theirs with mode `0700`.

## Attacks covered by tests

| Attack | Test | Result |
| --- | --- | --- |
| Plain-text request to a tracker | `tracker_integration_tests` | Connection dropped |
| Client pinned to the wrong key | `tracker_integration_tests`, `security_tests` | Handshake fails |
| Recorded request replayed on a new connection | `tracker_integration_tests` | Rejected |
| Non-TLS peer on the Raft port | `tracker_integration_tests` | No response |
| Tampered signature, wrong signer or changed transcript | `security_tests` | Rejected |
| Unknown user, wrong password, brute force | `tracker_state_tests` | Rejected or locked |

## Known limits

- **One key per file:** anyone who receives a file capability can download or seed that file. There is no per-peer identity, and no forward secrecy between peers.
- **Shared signing key:** `tracker_identity.key` is on every tracker. A compromised tracker can impersonate the cluster to clients until the key is rotated, which means regenerating `client.conf`.
- **No certificate revocation:** removing a node means issuing a new CA and certificates.
- **Peer clocks:** clocks must agree within 5 minutes for peer requests. Tracker traffic does not depend on clocks.

## Running the tests

```sh
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
```

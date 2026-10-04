# Security

Everything here uses OpenSSL's built-in primitives (already a dependency). There is no hand-rolled cryptography.

## The three links

| Link | Protection |
| --- | --- |
| Client to load balancer | Signed X25519 handshake, then AES-256-GCM under a fresh per-connection session key. |
| Load balancer and trackers | AES-256-GCM under a shared cluster key, 30 s timestamp. |
| Peer to peer | AES-256-GCM under the file's 256-bit capability, 30 s timestamp. |

## Keys

`torrent_keygen <config-dir>` creates:

- `cluster.key`: a random 256-bit key shared by the load balancer and the three trackers. Mode `0600`, git-ignored.
- `lb_identity.key`: the load balancer's Ed25519 private key. Mode `0600`, git-ignored.
- The matching Ed25519 public key is written as the second line of `client.conf`. Clients trust only this key ("pinning"), so nobody can pretend to be the load balancer.

## Client to load balancer handshake

One round trip at the start of every connection:

1. **Client hello:** `HELLO | client X25519 public key | 16-byte nonce | timestamp`. The X25519 key pair is new for this connection.
2. **Server hello:** `HELLO | server X25519 public key | 16-byte nonce | timestamp | signature`. The signature is Ed25519 over both hellos, made with the load balancer's identity key.
3. The client checks the signature against the pinned public key and that the timestamp is within 30 s. If either check fails, it disconnects.
4. Both sides compute `session key = SHA-256(X25519 shared secret || both hellos)`.
5. The request and the reply are AES-256-GCM under the session key, labelled `client->lb` and `lb->client` so one can't be reflected back as the other. A request that decrypts correctly proves the client holds the same key, so no separate confirmation message is needed.

The user's password is sent only inside this encrypted channel and is checked by the write server against a PBKDF2 hash.

**What this gives:**

- **Confidentiality:** passwords, session IDs and file capabilities are never on the wire in plain text.
- **Server authentication:** only the holder of `lb_identity.key` can produce a valid signature.
- **Client authentication:** the account password, sent inside the channel.
- **Freshness and replay protection:** each connection mixes new random keys and nonces from both sides, so a recorded request replayed on a new connection fails to decrypt. Stale hellos are rejected by timestamp.
- **Forward secrecy for tracker traffic:** the X25519 keys are thrown away after each connection. A later leak of `lb_identity.key` does not decrypt recorded sessions; it only lets the attacker impersonate the load balancer from then on.

## Cluster traffic

Every frame between the load balancer and the trackers, and between trackers, is:

```text
<unix-seconds> \t AES-256-GCM(cluster key, body, authenticated data = "cluster|" + timestamp)
```

Frames that fail to decrypt or are more than 30 s old are refused. Without the cluster key, nobody can read replicated passwords, push a fake snapshot to a read server, or forge replication entries. The load balancer forwards only client `C` commands, so a client can't send internal frames into the cluster through it.

## Peer traffic

Unchanged design: the tracker hands each group member the file's random 256-bit capability. It is now delivered over the encrypted channel. Peers use it as an AES-256-GCM key.

- **Opcode 21, request:** the group and file name are authenticated data. The operation, the piece index and a timestamp are encrypted. Seeders refuse requests older than 30 s (`60|stale`).
- **Opcode 30, response:** the bitmap or piece, authenticated against the original request and its nonce, so it can't be swapped for another response.
- **Opcode 60, rejection:** a short error with no file data.

## Other protections

- `RAND_bytes` generates every key, nonce, salt and session ID.
- Passwords are stored as PBKDF2-HMAC-SHA256 (random salt, 20,000 iterations) and compared in constant time.
- Five failed logins lock the account for 30 s.
- SHA-1 is used only for the piece and file integrity checks that the assignment requires.
- Resume manifests, which contain capabilities, are written with mode `0600`.
- The load balancer logs backend health only, never commands or passwords.

## Attacks covered by tests

- Plain-text request to the load balancer: connection dropped (`tracker_lb_integration_tests`).
- Client pinned to the wrong server key: handshake fails (`tracker_lb_integration_tests`).
- Recorded request replayed on a new connection: rejected (`tracker_lb_integration_tests`).
- Forged or unkeyed snapshot pushed to a read server: rejected, data unchanged (`tracker_integration_tests`).
- Tampered, wrong-key, stale or re-timestamped cluster frame: rejected (`security_tests`).
- Tampered signature, wrong signer or changed transcript: rejected (`security_tests`).
- Unknown user, wrong password, brute force: rejected or locked (`tracker_state_tests`).

## Known limits

- **One key per file.** Anyone who receives a file capability can download or seed that file. There is no per-peer identity, and no forward secrecy between peers.
- **One key for the cluster.** If any tracker or the load balancer is compromised, the whole cluster is.
- **Replay inside the 30 s window.** Within that window a cluster frame could be replayed. Replication sequence numbers make a replayed entry a harmless duplicate. A replayed snapshot is overwritten by the write server's next sync, at most 250 ms later.
- **Clock sync required.** Clocks must agree to within 30 s.

## Running the tests

```sh
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
```

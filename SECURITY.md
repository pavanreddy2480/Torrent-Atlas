# Security

This document describes every security mechanism in Torrent Atlas: what is protected, against whom, how, and where the limits are. For the overall design see [DESIGN.md](DESIGN.md).

All cryptography comes from **OpenSSL 3**. Tracker-to-tracker TLS uses NuRaft's asio transport with OpenSSL contexts that this project configures. Nothing cryptographic is hand-rolled.

---

## 1. What we protect

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Account passwords | Typed by users; stored only as PBKDF2 hashes | Account takeover |
| Session IDs | Tracker state, client memory | Act as a logged-in user |
| File capabilities (256-bit keys) | Tracker state, seeders, resume manifests | Read or seed a group's files |
| Group membership | Tracker state | Decides who may get capabilities |
| File contents | Peers' disks and the network | User data |
| Tracker cluster integrity | Raft log on 3 nodes | Forged entries could grant anyone anything |

## 2. Threat model

```text
                         ┌─────────────────────────────────────┐
   network attacker ───▶ │ can read, change, drop, replay and  │
   (on any link)         │ inject packets on every connection  │
                         └─────────────────────────────────────┘
   rogue client      ───▶ has an account, tries to reach groups or files
                          it was not admitted to
   rogue machine     ───▶ can reach the tracker ports but holds no
                          cluster certificate
   stolen disk/file  ───▶ attacker gets a copy of a tracker's data
                          directory or a client's resume manifest
```

**In scope:** eavesdropping, tampering, replay, impersonating a tracker, injecting Raft traffic, brute-forcing passwords, unauthorized access to groups and files.

**Out of scope:** a compromised tracker host (it holds the keys), a malicious group member who shares a capability on purpose, denial of service by flooding.

## 3. Keys and who holds them

`torrent_keygen <cluster.conf> <keys-dir> <client.conf>` creates everything:

```text
 keys-dir/
 ├── ca.crt                 cluster CA certificate (P-256, CN=torrent-cluster-ca)  public
 ├── ca.key                 CA private key          0600  keep OFFLINE after setup
 ├── node1.crt / node1.key  tracker 1 TLS identity  (CN=torrent-node-1)  key 0600
 ├── node2.crt / node2.key  tracker 2 TLS identity  (CN=torrent-node-2)  key 0600
 ├── node3.crt / node3.key  tracker 3 TLS identity  (CN=torrent-node-3)  key 0600
 └── tracker_identity.key   Ed25519 key that signs client handshakes     0600
 client.conf                tracker addresses + Ed25519 PUBLIC key (pinned)
```

| Key | Held by | Used for |
| --- | --- | --- |
| `ca.key` | Administrator only | Issuing node certificates |
| `ca.crt` | Every tracker | Checking other trackers' certificates |
| `node<id>.key` + `.crt` | That tracker only | Proving its identity in Raft TLS |
| `tracker_identity.key` | Every tracker | Signing the client handshake |
| Public key in `client.conf` | Every client | Checking that it is talking to the real cluster |
| File capability | Tracker, seeders and admitted members | AES-256-GCM key for that file's peer traffic |
| Session key | One client connection | AES-256-GCM key for one request and reply, then discarded |

```text
            ┌────────────┐ signs
            │  ca.key    │──────────┬──────────────┬──────────────┐
            └────────────┘          ▼              ▼              ▼
                              node1.crt      node2.crt      node3.crt
                                  └──── mutual TLS between trackers ──┘

            ┌──────────────────────┐ signs every handshake
            │ tracker_identity.key │───────────────▶ clients verify with the
            └──────────────────────┘                 public key in client.conf
```

`config/keys/` and `data/` are git-ignored.

---

## 4. Client to tracker channel

### 4.1 Handshake (one round trip per connection)

```text
 CLIENT                                                    TRACKER
   │ new X25519 key pair (c, C)                              │
   │ nonce Nc (16 B), time Tc                                │
   │                                                         │
   │──── HELLO | C | Nc | Tc ───────────────────────────────▶│
   │                                         new X25519 (s, S)
   │                                         nonce Ns, time Ts
   │                       transcript = "torrent-handshake-v1|" +
   │                                    client hello + "|" + S|Ns|Ts
   │                       sig = Ed25519(tracker_identity.key, transcript)
   │◀─── HELLO | S | Ns | Ts | sig ──────────────────────────│
   │                                                         │
   │ verify sig with the PINNED public key ── fail ─▶ drop   │
   │                                                         │
   │ shared = X25519(c, S)                    shared = X25519(s, C)
   │ K = SHA-256(shared || transcript)        K = SHA-256(shared || transcript)
   │ erase c and shared                       erase s and shared
   │                                                         │
   │──── AES-256-GCM(K, aad="client->tracker", "C\t<session>\t<cmd>") ─▶│
   │                                          decrypt fails ─▶ drop
   │◀─── AES-256-GCM(K, aad="tracker->client", "<reply>\t<session>") ───│
   │ connection closed, K erased                             │
```

### 4.2 What each step protects against

| Mechanism | Stops |
| --- | --- |
| Ed25519 signature over the whole transcript, checked against a **pinned** key | Impersonating a tracker; man in the middle; changing either hello in transit |
| Fresh X25519 keys on **both** sides | Replaying a recorded session (the session key differs every time) |
| Random nonces in the transcript | Duplicated handshakes; keeps transcripts unique |
| Session key from the X25519 secret plus the transcript | Using a key outside the handshake it came from |
| AES-256-GCM | Reading or changing the request or reply |
| Different labels per direction (`client->tracker`, `tracker->client`) | Reflecting a reply back as a request |
| Erasing ephemeral keys after use | Recovering past sessions later (**forward secrecy**) |
| The password sent only inside the sealed request | Password sniffing |

### 4.3 Forward secrecy

```text
 attacker records traffic today ─────────────┐
                                             ▼
 later steals tracker_identity.key ─▶ can it decrypt the recording?
                                      NO: the session key came from X25519
                                      keys that were erased; the identity key
                                      only SIGNED, it never encrypted anything.
                                      It can only impersonate the cluster from
                                      now on (rotate the key and client.conf).
```

### 4.4 Replay

```text
 attacker records:  HELLO₁ ─▶ … ─▶ sealed request R (under K₁)
 attacker replays:  HELLO₁ ─▶ tracker answers with NEW S₂, Ns₂ ─▶ K₂ ≠ K₁
                    sends R ─▶ decrypts under K₂? NO ─▶ connection dropped
```

Replay protection comes from fresh keys, not clocks, so client and tracker clocks do not need to agree. The timestamps in the hellos are recorded in the transcript but not used for replay checks.

---

## 5. Tracker to tracker (Raft) channel

### 5.1 Mutual TLS

```text
 tracker 1 (client side of RPC)                tracker 2 (server side)
   │──── TLS 1.3 ClientHello ────────────────────────▶│
   │◀─── ServerHello + node2.crt ──────────────────────│
   │ check: chains to ca.crt?                          │
   │        every subject in the chain is              │
   │        CN=torrent-cluster-ca or                   │
   │        CN=torrent-node-<id>?                      │
   │──── node1.crt + proof of key ───────────────────▶│
   │                       check: chains to ca.crt? (SSL_VERIFY_PEER |
   │                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
   │◀═══════════ encrypted Raft RPCs (votes, entries, snapshots) ═════▶│
```

- **TLS 1.3 minimum** (`SSL_CTX_set_min_proto_version`).
- **Both sides authenticate:** a connection without a cluster certificate fails during the handshake, before any Raft message is read.
- **Each node has its own key:** stealing one node's key does not reveal the others.

### 5.2 What this stops

| Attack | Result |
| --- | --- |
| Reading replicated password hashes, sessions or capabilities | Impossible: everything is encrypted |
| A rogue machine voting in elections or claiming leadership | Fails: no certificate |
| Injecting or editing log entries or snapshots | Fails: no certificate, and TLS integrity |
| A non-TLS client on the Raft port | Handshake fails, no reply (tested) |

### 5.3 Deterministic secrets in the log

The password salt, new session IDs and lockout timestamps are chosen by the leader and stored in the log entry (see [DESIGN.md §2.6](DESIGN.md#26-determinism-why-the-state-machine-takes-an-applycontext)). They are generated with `RAND_bytes` exactly once, and they travel only over mutual TLS.

---

## 6. Peer to peer channel

### 6.1 The capability

```text
 uploader: capability = RAND_bytes(32)         (one per file)
           upload_file … capability … ──▶ tracker (inside the sealed channel)
 member:   download_file …            ──▶ tracker checks membership
           ◀── META … capability …          (inside the sealed channel)
 non-member: download_file …          ──▶ ERR not a group member
```

The tracker hands the capability only to logged-in **members** of the group, and only over the encrypted client channel. It acts as the file's shared AES-256 key.

### 6.2 Request and response

```text
 downloader                                                    seeder
   │ plain = "GET\n<piece>\n<unix-seconds>"   (or BITMAP)        │
   │ aad   = "21|" + hex(group) + "|" + hex(file)                │
   │ C1    = AES-256-GCM(capability, aad, plain), nonce n1       │
   │──── 21 | hex(group) | hex(file) | n1 | C1 | tag ───────────▶│
   │                    look up the file; decrypt with its capability
   │                    bad tag ──▶ 60|aead
   │                    timestamp older than 5 min ──▶ 60|stale
   │                    piece not held ──▶ 60|unauthorized
   │                    aad2 = "30|" + aad + "|" + hex(n1)
   │                    C2 = AES-256-GCM(capability, aad2, piece bytes)
   │◀─── 30 | n2 | C2 | tag ──────────────────────────────────────│
   │ decrypt with aad2 (binds the reply to THIS request's nonce)  │
   │ SHA-1(piece) == hash from tracker?  no ─▶ discard, try another peer
```

| Mechanism | Stops |
| --- | --- |
| AES-256-GCM under the capability | Reading pieces on the wire; requests from anyone without the key |
| Group and file name in the authenticated data | Reusing a request against another file |
| Reply bound to the request nonce | Substituting a reply from another request |
| Timestamp checked within 5 minutes | Replaying an old captured request |
| SHA-1 per piece from the tracker, plus a full-file check | A malicious or buggy peer that holds the key sending wrong data |

### 6.3 Rejections

Every bad request gets a short `60|<reason>` with no file data: `malformed`, `encoding`, `unauthorized`, `aead`, `request`, `stale`, `piece`, `open`, `read`, `operation`, `encrypt`. `peer_rejection_test` sends malformed and unauthorized requests and checks for these replies.

---

## 7. Accounts and access control

### 7.1 Password storage

```text
 create_user alice secret
      │
      ▼
 salt  = 16 random bytes (chosen by the leader, stored in the log entry)
 hash  = PBKDF2-HMAC-SHA256(password, salt, 20 000 iterations, 32 bytes)
 store = "pbkdf2-sha256$20000$<salt hex>$<hash hex>"
 password string erased from memory (OPENSSL_cleanse)

 login: recompute with the stored salt ─▶ CRYPTO_memcmp (constant time)
```

- **Salts** stop precomputed (rainbow) tables and hide users who share a password.
- **20 000 iterations** slow down guessing if the hashes leak.
- **Constant-time comparison** avoids leaking how many bytes matched.

### 7.2 Brute-force lockout

```text
 wrong password ×5 ──▶ account locked for 30 s ──▶ every login refused
                        (even with the right password) until it expires
```

The counter and the lock time are part of the replicated state and are included in snapshots, so changing leaders does not reset them.

### 7.3 Who may do what

| Action | Check (on the leader) |
| --- | --- |
| Any group or file command | A valid session (`ERR login required`) |
| `list_requests`, `accept_request` | Caller owns the group |
| `upload_file`, `list_files`, `download_file` | Caller is a member |
| `stop_share` | Caller is a seeder of that file |
| `leave_group` | Caller is a member and not the owner; their shares in the group are removed |
| `logout` | Session ends; all the user's shares are removed |

Sessions are random 63-bit IDs. They are only ever sent inside the encrypted client channel.

---

## 8. Data at rest

| File | Contains | Protection |
| --- | --- | --- |
| `config/keys/*.key` | Private keys | Mode `0600`, git-ignored |
| `data/node<N>/` (tracker) | Raft log, snapshot: password hashes, sessions, capabilities | Directory created `0700`; files `0600`; hashes only, never passwords |
| `<dest>.resume` (client) | File capability, piece hashes | Mode `0600` |
| `<dest>.part` (client) | Partial file | Re-verified piece by piece on resume, so tampering can't inject data |

Tracker data is **not encrypted on disk**. Anyone who can read a tracker's data directory gets the password hashes, which are slow to crack, plus live sessions and file capabilities. Protect the host accordingly.

---

## 9. Attacks we test

| # | Attack | Test | Expected result |
| --- | --- | --- | --- |
| 1 | Plain-text command sent to a tracker | `tracker_integration_tests` | Connection dropped, no reply |
| 2 | Client pinned to the wrong public key | `tracker_integration_tests`, `security_tests` | Handshake fails |
| 3 | Recorded sealed request replayed on a new connection | `tracker_integration_tests` | Fails to decrypt, dropped |
| 4 | Non-TLS peer on the Raft port | `tracker_integration_tests` | Handshake fails, no reply |
| 5 | Tampered AES-GCM tag, ciphertext, nonce or AAD; wrong key | `security_tests` | Decryption fails |
| 6 | Tampered Ed25519 signature, wrong signer, changed transcript | `security_tests` | Verification fails |
| 7 | Wrong password, unknown user, 5 wrong attempts | `tracker_state_tests` | Rejected, then locked |
| 8 | Command without login; non-member listing, downloading or uploading; non-owner listing or accepting requests | `tracker_state_tests` | `ERR login required`, `ERR not a group member`, `ERR only owner may …` |
| 9 | Malformed or unauthorized peer request | `peer_rejection_test` | `60|…` with no data |

## 10. Known limits

| Limit | Impact | Possible fix |
| --- | --- | --- |
| One capability per file, never rotated | Anyone who was ever given it can download or seed that file, including after leaving the group | Rotate the capability when membership changes |
| No forward secrecy between peers | A leaked capability decrypts recorded piece traffic | Per-transfer X25519 between peers |
| `tracker_identity.key` is on all trackers | One compromised tracker can impersonate the cluster to clients | Per-node signing keys, with clients pinning the CA |
| No certificate revocation | Removing a node means a new CA and certificates | Short-lived certificates or a CRL |
| Tracker data not encrypted on disk | A stolen disk exposes hashes, sessions and capabilities | Disk encryption, or encrypt `snapshot.bin` and `raft.log` |
| SHA-1 for piece integrity | Weaker than SHA-256 against a peer crafting collisions | Move piece hashes to SHA-256 |
| Peer clocks must agree within 5 min | Requests from badly skewed peers are refused | Peer handshake with nonces instead of timestamps |
| Sessions never expire by time | A stolen session stays valid until logout | Session TTL |

## 11. Operational checklist

1. Run `torrent_keygen` on a trusted machine. Copy `node<id>.key`, `node<id>.crt`, `ca.crt` and `tracker_identity.key` to each tracker, and only `client.conf` to clients.
2. Move `ca.key` offline after generating certificates.
3. Keep `config/keys/` and `data/` readable only by the tracker's user.
4. If a tracker is compromised: generate new keys, replace everything, and give clients the new `client.conf`.
5. Run `ctest` after any change to the crypto or protocol code.

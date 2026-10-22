# Security

This document describes every security mechanism in Torrent Atlas: what is protected, against whom, how, and where the limits are. For the overall design see [DESIGN.md](DESIGN.md).

All cryptography comes from **OpenSSL 3**. Nothing cryptographic is hand-rolled.

---

## 1. What we protect

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Account passwords | Typed by users; stored only as PBKDF2 hashes | Account takeover |
| Session IDs | Tracker state, client memory | Act as a logged-in user |
| Peer keys (one random 256-bit key per running client) | That client's memory, tracker state | Minting peer tickets for that seeder |
| Peer tickets and their keys | The member who asked, for 5 minutes | Fetching one file from one seeder |
| Group membership | Tracker state | Decides who gets peer tickets |
| File contents | Peers' disks and the network | User data |

## 2. Threat model

```text
                         ┌─────────────────────────────────────┐
   network attacker ───▶ │ can read, change, drop, replay and  │
   (on any link)         │ inject packets on every connection  │
                         └─────────────────────────────────────┘
   rogue client      ───▶ has an account, tries to reach groups or files
                          it was not admitted to, or keeps going after
                          being removed
   stranger          ───▶ no account; can reach a peer's port and may hold
                          a ticket someone leaked
   stolen disk/file  ───▶ attacker gets a copy of the tracker's data
                          directory or a client's resume manifest
```

**In scope:** eavesdropping, tampering, replay, impersonating the tracker, brute-forcing passwords, unauthorized access to groups and files, access after leaving or being removed, probing peers for which files they hold.

**Out of scope:** a compromised tracker host (it holds the keys), a current member who copies a file out and hands it on, denial of service by flooding.

## 3. Keys and who holds them

`torrent_keygen <tracker IP:PORT> <keys-dir> <client.conf>` creates the tracker's key:

```text
 keys-dir/
 └── tracker_identity.key   Ed25519 key that signs client handshakes     0600
 client.conf                tracker address + Ed25519 PUBLIC key (pinned)
```

| Key | Held by | Used for |
| --- | --- | --- |
| `tracker_identity.key` | The tracker | Signing the client handshake |
| Public key in `client.conf` | Every client | Checking that it is talking to the real tracker |
| Session key | One client connection | AES-256-GCM key for one request and reply, then discarded |
| Peer key | One running client, and the tracker | Deriving the keys of tickets for that seeder; a new one every run |
| Ticket key | The member a ticket was issued to | AES-256-GCM key for that member's requests to one seeder, for 5 minutes |

```text
            ┌──────────────────────┐ signs every handshake
            │ tracker_identity.key │───────────────▶ clients verify with the
            └──────────────────────┘                 public key in client.conf

            ┌──────────────┐ HMAC   ┌──────────────────────────────┐
            │ peer key kA  │───────▶│ ticket key for (user, group, │──▶ only for seeder A
            │ (seeder A)   │        │ file, expiry)                │
            └──────────────┘        └──────────────────────────────┘
```

`config/keys/`, `config/client.conf` and `data/` are git-ignored.

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
                                      It can only impersonate the tracker from
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

## 5. Peer to peer channel

### 5.1 Peer tickets

Seeders do not share a key with downloaders. Each running client makes a random 32-byte **peer key** and gives it to the tracker, inside the sealed channel, whenever it shares a file. When a member asks for a file, the tracker issues one ticket per seeder:

```text
 member B:   download_file demo song.mp3 ──▶ tracker
             tracker: logged in? member of demo? ── no ─▶ ERR not a group member
             ticket = hex(B) . hex(demo) . hex(song.mp3) . <now + 300>
             key    = HMAC-SHA256(seeder's peer key, "torrent-peer-ticket-v1|" + ticket)
             ◀── META … <seeder ip:port>/<ticket>/<hex key>, …   (sealed)
 non-member: download_file …          ──▶ ERR not a group member
```

| Property | Why it holds |
| --- | --- |
| Only the tracker can issue a ticket a seeder accepts | Only the tracker and that seeder know the peer key |
| A ticket can't be edited (other user, file or a later expiry) | The key is an HMAC over the whole ticket text |
| A ticket is useless at another seeder | Each seeder has its own peer key |
| Access ends when membership does | `remove_member` and `leave_group` stop new tickets at once; old ones expire within 5 minutes; a long download must keep getting fresh tickets |
| Nothing long-lived ever reaches a member | The member gets ticket keys only; a leaked one works for one file at one seeder for at most 5 minutes |
| A peer key leaks only if its client's memory or the tracker's state leaks | It is never sent to peers and changes every run |

### 5.2 Request and response

```text
 downloader                                                    seeder
   │ plain = "GET\n<piece>\n<unix-seconds>"   (or BITMAP)        │
   │ aad   = "21|" + ticket                                      │
   │ C1    = AES-256-GCM(ticket key, aad, plain), nonce n1       │
   │──── 21 | ticket | n1 | C1 | tag ───────────────────────────▶│
   │                    parse the ticket; expired? ──▶ 60|denied
   │                    key = HMAC(own peer key, ticket)
   │                    decrypt; bad tag ──▶ 60|denied
   │                    timestamp older than 5 min ──▶ 60|denied
   │                    not sharing that group/file ──▶ 60|denied
   │                    piece not held ──▶ 60|unavailable
   │                    aad2 = "30|" + aad + "|" + hex(n1)
   │                    C2 = AES-256-GCM(ticket key, aad2, piece bytes)
   │◀─── 30 | n2 | C2 | tag ──────────────────────────────────────│
   │ decrypt with aad2 (binds the reply to THIS request's nonce)  │
   │ SHA-1(piece) == hash from tracker?  no ─▶ discard, try another peer
```

| Mechanism | Stops |
| --- | --- |
| A tracker-issued ticket on every request | Requests from anyone the tracker did not just admit, including people removed from the group |
| AES-256-GCM under the ticket key | Reading pieces on the wire |
| The ticket (user, group, file, expiry) in the authenticated data | Reusing a request for another file |
| Reply bound to the request nonce | Substituting a reply from another request |
| Timestamp checked within 5 minutes | Replaying an old captured request later |
| SHA-1 per piece from the tracker, plus a full-file check | A malicious or buggy seeder sending wrong data |

### 5.3 One answer for every rejection

Before a request is known to be genuine, every failure gets exactly `60|denied`: a malformed frame, a bad or expired ticket, a wrong key, a stale timestamp, or a file the peer is not sharing. The seeder checks the ticket and decrypts **before** it looks the file up, so a stranger cannot tell "no such file" from "wrong key" and cannot list what a peer holds. Only a request with a valid ticket can get the other answer, `60|unavailable` (that piece isn't here). `peer_access_tests` and `peer_rejection_test` check that these replies are byte-for-byte identical.

---

## 6. Accounts and access control

### 6.1 Password storage

```text
 create_user alice secret
      │
      ▼
 salt  = 16 random bytes
 hash  = PBKDF2-HMAC-SHA256(password, salt, 20 000 iterations, 32 bytes)
 store = "pbkdf2-sha256$20000$<salt hex>$<hash hex>"
 password string erased from memory (OPENSSL_cleanse)

 login: recompute with the stored salt ─▶ CRYPTO_memcmp (constant time)
```

- **Salts** stop precomputed (rainbow) tables and hide users who share a password.
- **20 000 iterations** slow down guessing if the hashes leak.
- **Constant-time comparison** avoids leaking how many bytes matched.

### 6.2 Brute-force lockout

```text
 wrong password ×5 ──▶ account locked for 30 s ──▶ every login refused
                        (even with the right password) until it expires
```

The counter and the lock time are part of the saved tracker state, so restarting the tracker does not reset them.

### 6.3 Who may do what

| Action | Check (on the tracker) |
| --- | --- |
| Any group or file command | A valid session (`ERR login required`) |
| `list_requests`, `accept_request` | Caller owns the group |
| `remove_member` | Caller owns the group; the owner can't be removed; the removed user's shares in the group are removed and they get no more tickets |
| `upload_file`, `list_files`, `download_file` | Caller is a member |
| `stop_share` | Caller is a seeder of that file |
| `leave_group` | Caller is a member and not the owner; their shares in the group are removed and they get no more tickets |
| `logout` | Session ends; all the user's shares are removed |

Sessions are random 63-bit IDs. They are only ever sent inside the encrypted client channel.

---

## 7. Data at rest

| File | Contains | Protection |
| --- | --- | --- |
| `config/keys/*.key` | Private keys | Mode `0600`, git-ignored |
| `data/tracker.state` | Password hashes, sessions, lockouts, groups, file metadata, seeders' addresses and peer keys | Directory created `0700`; file `0600`; written atomically |
| `<dest>.resume` (client) | Group and file name, piece hashes, verified bitmap; no keys | Mode `0600` |
| `<dest>.part` (client) | Partial file | Re-verified piece by piece on resume, so tampering can't inject data |

**No password is ever written to disk.** The tracker saves only its serialized state, never the commands it received, so the passwords inside `create_user` and `login` stay in memory, are hashed or checked, and are erased (`OPENSSL_cleanse`). `tracker_integration_tests` signs up, fails a login and logs in, then scans every file in the data directory for the typed passwords, plain and hex-encoded.

Tracker data is **not encrypted on disk**. Anyone who can read `tracker.state` gets the password hashes, which are slow to crack, plus live sessions and the peer keys of seeders that are online, which would let them mint tickets for those seeders until the seeders restart. Protect the host accordingly.

---

## 8. Attacks we test

| # | Attack | Test | Expected result |
| --- | --- | --- | --- |
| 1 | Plain-text command sent to the tracker | `tracker_integration_tests` | Connection dropped, no reply |
| 2 | Client pinned to the wrong public key | `tracker_integration_tests`, `security_tests` | Handshake fails |
| 3 | Recorded sealed request replayed on a new connection | `tracker_integration_tests` | Fails to decrypt, dropped |
| 4 | Looking for typed passwords in the tracker's data directory | `tracker_integration_tests` | Not found, plain or hex |
| 5 | Tampered AES-GCM tag, ciphertext, nonce or AAD; wrong key | `security_tests` | Decryption fails |
| 6 | Tampered Ed25519 signature, wrong signer, changed transcript | `security_tests` | Verification fails |
| 7 | Wrong password, unknown user, 5 wrong attempts | `tracker_state_tests` | Rejected, then locked |
| 8 | Command without login; non-member listing, downloading or uploading; non-owner listing, accepting or removing | `tracker_state_tests` | `ERR login required`, `ERR not a group member`, `ERR only owner may …` |
| 9 | Removed member asks for the file again | `tracker_state_tests`, `client_integration_tests` | `ERR not a group member`; their own shares are dropped |
| 10 | Peer request with a guessed key, an edited ticket, a stretched expiry, or an expired ticket | `peer_access_tests`, `client_integration_tests` | `60\|denied` |
| 11 | Probing a peer for a file it has vs one it doesn't | `peer_access_tests`, `peer_rejection_test` | Identical `60\|denied` |

## 9. Known limits

| Limit | Impact | Possible fix |
| --- | --- | --- |
| Revocation is not instant at the seeder | A removed member's tickets keep working for up to 5 minutes | Shorter tickets, or seeders asking the tracker |
| No forward secrecy between peers | Someone who later gets a seeder's peer key (from its memory or the tracker's disk) and recorded the traffic can decrypt it | Per-transfer X25519 between peers |
| A peer request can be replayed while its ticket and timestamp are valid | The replayer gets an encrypted piece it can't read | Remember recent request nonces |
| Single tracker | If it is down, nobody can log in or start a download | Run it under a supervisor; keep backups of `data/` |
| Tracker data not encrypted on disk | A stolen disk exposes hashes, sessions and online seeders' peer keys | Disk encryption |
| SHA-1 for piece integrity | Weaker than SHA-256 against a peer crafting collisions | Move piece hashes to SHA-256 |
| Peer clocks must agree within 5 min | Requests from badly skewed peers are refused | Peer handshake with nonces instead of timestamps |
| Sessions never expire by time | A stolen session stays valid until logout | Session TTL |

## 10. Operational checklist

1. Run `torrent_keygen` on the tracker's machine. Give clients only `client.conf`.
2. Keep `config/keys/` and `data/` readable only by the tracker's user.
3. If the tracker is compromised: generate a new key, give clients the new `client.conf`, and have every user restart their client so it makes a new peer key.
4. Run `ctest` after any change to the crypto or protocol code.

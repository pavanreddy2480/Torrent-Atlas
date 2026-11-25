# Wire protocol

Every byte that travels between the programs, read from the code on `main`
(commit 81b1c66). Example values are made up, but their lengths are exact.

Contents

1. [Who talks to whom](#1-who-talks-to-whom)
2. [Layer 0: the frame (how anyone knows how much to read)](#2-layer-0-the-frame)
3. [Layer 1: the tracker handshake (HELLO)](#3-layer-1-the-tracker-handshake)
4. [Layer 2: encrypted tracker frames](#4-layer-2-encrypted-tracker-frames)
5. [Layer 3: tracker commands, every message](#5-layer-3-tracker-commands)
6. [Peer to peer: tickets, 21 / 30 / 60](#6-peer-to-peer)
7. [One whole download, start to finish](#7-one-whole-download)
8. [Your questions, answered](#8-your-questions-answered)

---

## 1. Who talks to whom

```text
     torrent_keygen   (runs once, offline: sends NOTHING over the network)
        |                                  |
   writes keys/tracker_identity.key   writes client.conf
   (Ed25519 PRIVATE key, 64 hex)      ("127.0.0.1:6000" + Ed25519 PUBLIC key)
        |                                  |
        v                                  v   copied to every client
 +-------------+
 |   tracker   |   users, sessions, groups, seeders - all in memory
 +-------------+
    ^       ^
    |       |    link A: client <-> tracker
    |       |    new TCP connection per command, HELLO handshake,
    |       |    then ONE encrypted request and ONE encrypted reply
    v       v
 +--------+  +--------+
 | client |  | client |   each client = prompt + TrackerClient
 |  Alice |  |  Bob   |                + PeerServer (uploads to others)
 +--------+  +--------+                + PeerClient (downloads from others)
     ^            |
     +------------+      link B: peer <-> peer
                         new TCP connection per piece request,
                         NO handshake: one "21" frame, one "30"/"60" frame
```

There are only two kinds of conversation: link A and link B. Both sit on
the same framing (section 2).

---

## 2. Layer 0: the frame

**Every** message on both links, including the plaintext HELLO, is sent as
a frame (`Socket::sendFrame` / `receiveFrame`, `common/net/net.cpp`):

```text
 byte:   0        1        2        3        4 ...................... 4+N-1
       +--------+--------+--------+--------+------------------------------+
       |   N, unsigned 32-bit, big-endian  |   N bytes of payload         |
       +--------+--------+--------+--------+------------------------------+
        \_________ length prefix _________/ \__ the message itself ______/
```

How the receiver reads one message:

```text
  recv exactly 4 bytes  ->  N = ntohl(those 4 bytes)
  N > 16 777 216 (16 MiB)?  ->  drop the connection (no huge allocation)
  recv exactly N bytes  ->  that is the message
```

| Field | Size | Why |
| --- | --- | --- |
| length | 4 bytes | TCP is a byte stream with no message boundaries. A fixed 4-byte prefix tells the reader exactly how many bytes belong to this message, so it never reads too little or into the next message. Big-endian ("network order") so both machines agree. 4 bytes is enough for a 2 MiB piece (about 2.7 MiB as base64); 2 bytes (64 KiB) would not be. |
| payload | N bytes | The message. Binary or text; the frame doesn't care. |

The frame says nothing about encryption. **Whether a payload is encrypted
is decided by its position in the conversation, not by a flag** (see
section 4).

---

## 3. Layer 1: the tracker handshake

Code: `common/net/secure_channel.cpp`. Happens at the start of **every**
client-to-tracker TCP connection.

### 3.1 The exchange

```text
 client                                                   tracker
 (SecureChannel::connect)                                 (SecureChannel::accept)
   |                                                         |
   | new X25519 key pair (cpriv, cpub), 16 random bytes cnonce
   |                                                         |
   |  frame 1, PLAINTEXT                                     |
   |  00 00 00 72  "HELLO|<cpub>|<cnonce>|<time>"            |
   |-------------------------------------------------------->|
   |                                                         | checks fields + time
   |                                                         | new X25519 pair (spriv, spub), snonce
   |                                                         | T   = transcript (below)
   |                                                         | sig = Ed25519-sign(identity key, T)
   |  frame 2, PLAINTEXT                                     |
   |  00 00 00 F3  "HELLO|<spub>|<snonce>|<time>|<sig>"      |
   |<--------------------------------------------------------|
   | checks fields + time                                    |
   | rebuilds T, verifies sig with the PINNED public key     |
   | from client.conf; wrong -> hang up                      |
   |                                                         |
   |   both sides now compute, without sending anything:     |
   |   shared = X25519(own private, other's public)          |
   |   key    = SHA-256(shared || T)          (32 bytes)     |
   |   erase own private key and shared                      |
   |                                                         |
   |  frame 3, ENCRYPTED with key (section 4)                |
   |=========================================================>|
   |  frame 4, ENCRYPTED with key                            |
   |<=========================================================|
   x close (the key is erased)                               x close
```

### 3.2 Exact bytes

Client HELLO (114 bytes of payload, so the prefix is `00 00 00 72`):

```text
HELLO|8f3a6c...(64 hex)...e21b|5c0e9a77d41f2b8803c6e5a1f9d2b047|1762779000
\___/ \______ cpub _________/  \__________ cnonce __________/  \__time__/
  5   1         64             1             32                1    10    = 114
```

Tracker HELLO (243 bytes, prefix `00 00 00 F3`):

```text
HELLO|1d77b0...(64 hex)...a90c|e4c1083b5f6a29d7710ce8b4a3f05d92|1762779000|3b9f...(128 hex)...0e7a
\___/ \______ spub _________/  \__________ snonce __________/  \__time__/ \______ sig ________/
```

Transcript T that the tracker signs and both sides hash into the key:

```text
torrent-handshake-v1|HELLO|<cpub>|<cnonce>|<ctime>|<spub>|<snonce>|<stime>
\_ protocol label __/ \__ client's whole hello __/ \_ tracker's 3 fields _/
```

### 3.3 Why each field

| Field | Size | Why it is there |
| --- | --- | --- |
| `HELLO` | 5 chars | Tells the reader this really is a handshake message, so a stray or wrong-protocol connection is rejected at once. |
| `cpub` / `spub` | 32 bytes, 64 hex | Ephemeral X25519 public keys, new for every connection. Each side combines its own private key with the other's public key and gets the same secret, which never crosses the wire. Because they are thrown away after the connection, a recording of the traffic can't be decrypted later even if the tracker's identity key leaks (forward secrecy). |
| `cnonce` / `snonce` | 16 bytes, 32 hex | Random per hello. They make every transcript unique, so a tracker signature recorded from one connection can never be valid for another, and they add randomness to the key even if a key pair were somehow reused. |
| `time` | decimal Unix seconds | Must be within 300 s of the receiver's clock (`isFreshTimestamp`). Limits how long a recorded hello stays usable, while tolerating clock skew. |
| `sig` (tracker only) | 64 bytes, 128 hex | Ed25519 signature over T with the tracker's long-term identity key. The client checks it with the public key pinned in client.conf. This is the only thing that stops someone pretending to be the tracker (man in the middle): an impostor can send its own `spub`, but it can't sign for it. The client has no key, so it doesn't sign; clients prove who they are with a password later. |
| `torrent-handshake-v1` | label | Ties the signature to this protocol and version, so a signature made for some other purpose can't be passed off as a handshake. |
| hex everywhere | | Keeps the hello pure text with `|` separators; raw key bytes could contain a `|`. |

The HELLO is plaintext on purpose: no key exists yet. Nothing in it is
secret (public keys, random nonces, a time, a signature).

---

## 4. Layer 2: encrypted tracker frames

After the two HELLOs, each side sends exactly one more frame, encrypted with
AES-256-GCM under the session key. The payload is **binary, not hex**:

```text
 0          12                     28                            28+L
 +----------+----------------------+------------------------------+
 |  nonce   |        tag           |   ciphertext (L bytes)       |
 | 12 bytes |      16 bytes        |   same length as plaintext   |
 +----------+----------------------+------------------------------+
 AAD (authenticated, never sent): "client->tracker"  or  "tracker->client"
```

| Field | Size | Why |
| --- | --- | --- |
| nonce | 12 bytes, random | GCM must never use the same nonce twice with one key. It is random and travels in front so the receiver can decrypt. It is not secret. 12 bytes is the size GCM is designed for. |
| tag | 16 bytes | The authentication code. Decryption fails if one bit of nonce, ciphertext or AAD has changed, so tampering is detected, not just hidden. |
| ciphertext | L bytes | The encrypted request or reply. |
| AAD | not sent | The direction label. Both sides know it, so it costs no bytes, but a frame sealed as `client->tracker` won't open as `tracker->client`. That stops an attacker reflecting the client's own frame back at it. |

**How the tracker knows a frame is encrypted:** it doesn't inspect the
bytes. `tracker/main.cpp` runs a fixed order: `accept()` reads frame 1 as a
plaintext HELLO and writes frame 2; then `receive()` treats frame 3 as
encrypted. Any frame that fails the GCM check is rejected, so plaintext sent
where ciphertext is expected just fails.

Example: request `C\t0\tlogin alice s3cret` is 22 bytes, so the frame is
28 + 22 = 50 bytes, prefix `00 00 00 32`.

---

## 5. Layer 3: tracker commands

Inside the encrypted frame (code: `TrackerClient::request`,
`TrackerService::handle`):

```text
request:  C <TAB> <session id> <TAB> <command line>
reply:    <response text> <TAB> <session id after the command>
```

| Field | Why |
| --- | --- |
| `C` | Marks a client command. Anything else gets `ERR malformed request`. |
| session id | Decimal. 0 = not logged in. Otherwise the number the tracker handed out at login. The TCP connection is closed after every command, so this number is how the tracker knows a new connection belongs to the same logged-in user. |
| command line | Words separated by spaces, exactly what the user typed except for the hex fields shown below. |
| reply session | The tracker always sends back the session after the command: the new id after `login`, 0 after `logout`, unchanged otherwise. The client simply stores whatever comes back. |
| TAB | The separator. Commands use spaces between words, so a TAB never collides with them. |

Every command below is a separate TCP connection with its own HELLO pair
(section 3). In the diagrams that is written `[HS]`. The arrows show the
**plaintext inside** the encrypted frames.

### 5.1 create_user

```text
 Alice                                              tracker
   | [HS]                                              |
   |== C\t0\tcreate_user alice s3cret ================>|  salt = 16 random bytes
   |                                                   |  store pbkdf2-sha256$20000$<salt>$<hash>
   |                                                   |  erase "s3cret"
   |<= OK user created\t0 =============================|
```

Fields: `alice` = user name, `s3cret` = password. It is safe to send because
the frame is encrypted. The tracker keeps only a salted PBKDF2 hash. The log
shows `create_user alice ***`.
Errors: `ERR user already exists`, `ERR secure random generation failed`,
`ERR usage: create_user <user> <password>`.

### 5.2 login

```text
 Alice                                              tracker
   | [HS]                                              |
   |== C\t0\tlogin alice s3cret ======================>|  check the password hash
   |                                                   |  sid = random 63-bit number
   |                                                   |  sessions[sid] = "alice"
   |<= OK logged in\t8312093445127730114 ==============|
   | client stores 8312093445127730114                 |
```

Why 63 random bits: the session id is a bearer token, so whoever presents
it acts as Alice. It must be unguessable. 63 bits (top bit cleared) still
fits a signed 64-bit integer.
Errors: `ERR no such user`, `ERR invalid password`,
`ERR logout before logging in again`.

### 5.3 logout

```text
   |== C\t8312093445127730114\tlogout ================>|  remove alice from every file's seeders
   |                                                   |  erase the session
   |<= OK logged out\t0 ===============================|  client stores 0, stops serving files
```

Error: `ERR not logged in`.

### 5.4 Groups

```text
 Alice (owner)                     tracker                          Bob
   |== C\t<A>\tcreate_group demo ==>|                                  |
   |<= OK group created\t<A> =======| owner=alice members={alice}      |
   |                                |<== C\t<B>\tjoin_group demo ======|
   |                                |=== OK join requested\t<B> ======>| pending={bob}
   |== C\t<A>\tlist_requests demo ==>|                                 |
   |<= OK bob\t<A> =================|                                  |
   |== C\t<A>\taccept_request demo bob>                                |
   |<= OK request accepted\t<A> ====| members={alice,bob}              |
   |                                |<== C\t<B>\tlist_groups ==========|
   |                                |=== OK demo\t<B> ================>|
   |                                |<== C\t<B>\tleave_group demo =====|
   |                                |=== OK left group\t<B> ==========>| bob's shares in demo dropped
```

| Command | Who may | Reply | Errors |
| --- | --- | --- | --- |
| `create_group <g>` | logged in | `OK group created` | `ERR group already exists` |
| `join_group <g>` | logged in | `OK join requested` | `ERR no such group`, `ERR already a member`, `ERR request already pending` |
| `leave_group <g>` | member, not owner | `OK left group` | `ERR no such group`, `ERR owner cannot leave group`, `ERR not a member` |
| `list_groups` | logged in | `OK g1 g2 ...` | |
| `list_requests <g>` | owner | `OK u1 u2 ...` | `ERR no such group`, `ERR only owner may list requests` |
| `accept_request <g> <u>` | owner | `OK request accepted` | `ERR no such group`, `ERR only owner may accept requests`, `ERR no such pending request` |
| `remove_member <g> <u>` | owner | `OK member removed` | `ERR no such group`, `ERR only owner may remove members`, `ERR owner cannot be removed`, `ERR not a member` |

Every command except `create_user`, `login` and `logout` first answers
`ERR login required` if the session id is unknown. A wrong number of words
gets `ERR usage: ...`, and an unknown command gets `ERR unknown command`.

### 5.5 upload_file (become a seeder)

The user types `upload_file demo ./notes.txt`. The client hashes the file,
then sends:

```text
 Alice                                                       tracker
   | [HS]                                                       |
   |== C\t<A>\tupload_file demo 6e6f7465732e747874 1048576      |
   |      2fd4e1c67a2d28fced849ee1bb76e7391b93eb12              |
   |      a94a8fe5ccb19ba61c4c0873d391e987982fbbd3,             |
   |      9bc34549d565d9505b287de0cd20ac77be1d3f2c              |
   |      127.0.0.1 7001                                        |
   |      4b1e...(64 hex)...c07d ==============================>|  member? metadata valid?
   |                                                            |  seeders[alice] =
   |                                                            |    {127.0.0.1:7001, peer key}
   |<= OK file shared\t<A> =====================================|
   | only now: PeerServer starts serving notes.txt             |
```

(The line breaks are only for reading; on the wire it is one line, one
space between fields.)

| Field | Example | Why |
| --- | --- | --- |
| group | `demo` | Files are shared per group; only members get to download. |
| name, hex | `6e6f7465732e747874` = `notes.txt` | Hex, because a file name could contain spaces, which would break the space-separated command. |
| size | `1048576` | Bytes. Lets the downloader pre-size the file and work out the piece count. |
| full SHA-256 | 64 hex | Checks the finished file. |
| piece hashes | 64 hex each, comma-joined (`-` if the file is empty) | One per 2 MiB piece. Each piece is checked as it arrives, so one bad seeder can't corrupt the file. |
| ip, port | `127.0.0.1 7001` | Where Alice's PeerServer listens, so downloaders can reach it. |
| peer key, hex | 64 hex = 32 bytes | A random secret Alice made when her client started. Only the tracker ever sees it. It is what lets the tracker issue tickets that Alice can check later without asking the tracker (section 6). |

The first upload of a name fixes its metadata. Later uploads (more seeders)
must match exactly, or they get `ERR conflicting file metadata`. Other
errors: `ERR no such group`, `ERR not a group member`,
`ERR invalid upload metadata`. The log hides everything after the name.

### 5.6 list_files and stop_share

```text
   |== C\t<B>\tlist_files demo =======================>|
   |<= OK 6e6f7465732e747874\t<B> =====================|   client prints "notes.txt"
   |== C\t<A>\tstop_share demo 6e6f7465732e747874 ====>|   client hex-encodes the name
   |<= OK sharing stopped\t<A> ========================|   file removed if no seeders remain
```

Errors: `ERR no such group`, `ERR not a group member` (list);
`ERR invalid group/file`, `ERR you are not sharing this file` (stop).

### 5.7 download_file (the tracker issues tickets)

```text
 Bob                                                         tracker
   | [HS]                                                       |
   |== C\t<B>\tdownload_file demo 6e6f7465732e747874 ==========>|  Bob a member? any seeders?
   |                                                            |  ticket = hex(bob).hex(demo)
   |                                                            |       .hex(notes.txt).<now+300>
   |                                                            |  for each seeder S:
   |                                                            |    key_S = HMAC-SHA256(peerKey_S,
   |                                                            |      "torrent-peer-ticket-v1|"+ticket)
   |<= META 1048576 2fd4...eb12 a94a...bbd3,9bc3...3f2c         |
   |      127.0.0.1:7001/626f62.64656d6f.6e6f7465732e747874.1762779300/<key_Alice 64 hex>,
   |      127.0.0.1:7003/626f62.64656d6f.6e6f7465732e747874.1762779300/<key_Carol 64 hex>
   |      \t<B> ===================================================|
```

Reply layout:

```text
META <size> <full sha256> <piece hashes> <seeder>,<seeder>,...
                                       \_ each: <ip:port>/<ticket>/<request key hex> _/
```

| Field | Why |
| --- | --- |
| `META` | Says this is file data, not `OK`/`ERR`. |
| size, hashes | The same metadata the first uploader sent; Bob verifies pieces against it. |
| ip:port | Where to connect for this seeder. |
| ticket | The permission slip Bob will show the seeder (section 6). Same text for every seeder. |
| request key | The key Bob encrypts with when talking to that seeder. Different per seeder, because each seeder has a different peer key. It is safe here only because this whole reply is inside the encrypted tracker frame. |

Errors: `ERR no such group`, `ERR not a group member`,
`ERR invalid file name`, `ERR file has no online seeders`,
`ERR could not issue peer tickets`. The tracker log prints just `META ...`.

---

## 6. Peer to peer

Code: `client/peer/peer_protocol.*`, `peer_server.cpp`, `peer_client.cpp`,
`common/peer_ticket.*`. One request frame and one reply frame per TCP
connection. There is no handshake: the ticket and its key replace it.

### 6.1 The ticket

```text
626f62 . 64656d6f . 6e6f7465732e747874 . 1762779300
 user     group        file name          expires (Unix seconds, now + 300)
 "bob"    "demo"       "notes.txt"
```

Hex keeps `.` and `|` out of the fields. The ticket is **not secret** and
**not encrypted**: it travels in clear. What makes it trustworthy is its key:

```text
key = HMAC-SHA256( seeder's peer key ,  "torrent-peer-ticket-v1|" + ticket )
```

Only two parties know the seeder's peer key: the seeder and the tracker. So
only the tracker could have computed this key for this ticket.

### 6.2 Request: `21`

```text
21|<ticket>|<nonce base64 16>|<ciphertext base64>|<tag base64 24>
```

Exact example, `GET` of piece 3 (115 bytes, prefix `00 00 00 73`):

```text
21|626f62.64656d6f.6e6f7465732e747874.1762779300|obLD1OX2BxgpOktc|<24 base64>|<24 base64>
```

```text
plaintext inside (encrypted with the request key):
   GET\n3\n1762779012          or     BITMAP\n0\n1762779012
   op   piece  time                   op      (ignored) time

AAD (authenticated, not sent again):  21|<ticket>
```

| Field | Why |
| --- | --- |
| `21` | Message type: request. |
| ticket, clear | The seeder needs it **before** it can decrypt, to work out which key to use. |
| nonce | 12 random bytes for GCM, as in section 4. Also reused in the reply's AAD (6.3). |
| ciphertext | The operation, piece index and time, hidden from anyone watching. |
| tag | Proves the frame was sealed by someone holding the request key. |
| AAD = `21|ticket` | The ticket isn't encrypted but is authenticated: change one character of it (say, a later expiry) and the tag fails. |
| time inside | Must be within 300 s. A recorded request replayed later is refused. |

### 6.3 Reply: `30`, `60|denied`, `60|unavailable`

```text
30|<nonce base64 16>|<ciphertext base64>|<tag base64 24>
   plaintext: BITMAP -> one byte per piece, 01 = have, 00 = don't
              GET    -> the piece's raw bytes (up to 2 MiB, so ~2.7 MiB in base64)
   AAD: 30|21|<ticket>|<request nonce as hex text>

60|denied           plain text, not encrypted
60|unavailable      plain text, not encrypted
```

Sizes: a BITMAP reply for 4 pieces is 53 bytes; a full 2 MiB GET reply is
3 + 16 + 1 + 2 796 204 + 1 + 24 = 2 796 249 bytes, well under the 16 MiB cap.

Why base64 and not hex: the frame is split on `|`, so the binary fields have to
be turned into text that never contains `|`. Base64 does that at 1.33x the size
of the data (hex is 2x) and decodes much faster. On the ablation benchmark,
hex was 2.6x slower and sent 135 MB instead of 90 MB for a 64 MB file
(`docs/ablations/RESULTS.md`).

| Field | Why |
| --- | --- |
| `30` | Success. |
| AAD includes the request nonce | The reply is bound to this one request. A recorded reply to "GET 3" can't be fed back as the answer to a later "GET 5". |
| `60|denied` | One identical answer to every bad request: malformed, bad ticket, forged key, expired, replayed, or a file not shared here. A stranger learns nothing, not even which files this peer has. |
| `60|unavailable` | The ticket was fine but this peer lacks the piece (or can't read it). The downloader just tries another seeder. |

### 6.4 How the seeder validates a ticket

The **seeder** (Alice's PeerServer) does this, not the downloader. Alice's
client never asks the tracker; it checks the maths alone
(`PeerServer::respond`):

```text
 frame "21|ticket|nonce|ct|tag" arrives
   |
   |- 5 fields, first is "21"? ...................... no -> 60|denied
   |- ticket decodes into user, group, file, expiry? . no -> 60|denied
   |- now < expiry? ................................. no -> 60|denied
   |
   |- key = HMAC(MY peer key, "torrent-peer-ticket-v1|" + ticket)
   |- GCM-decrypt(key, AAD "21|"+ticket) succeeds? ... no -> 60|denied
   |     this is THE authenticity check: Bob could only have sealed
   |     the frame with this key if the tracker gave it to him,
   |     because nobody else knows my peer key
   |
   |- 3 lines inside, time within 300 s, piece is a number? no -> 60|denied
   |- am I sharing (ticket.group, ticket.file)? ...... no -> 60|denied
   |- BITMAP  -> 30 with bitmap
   |- GET, piece in range and I have it -> 30 with piece bytes
   |- otherwise -> 60|unavailable
```

Why this works:

```text
   tracker knows peerKey_Alice  (Alice gave it in upload_file)
        |
        | key = HMAC(peerKey_Alice, ticket)    -- sent to Bob inside META,
        v                                          encrypted, after checking
   Bob holds (ticket, key)                         Bob is a group member
        |
        | seals request with key, sends ticket in clear
        v
   Alice recomputes HMAC(peerKey_Alice, ticket) = the same key
        -> decrypts fine   -> the tracker issued this ticket
        -> fails           -> forged, edited, or meant for another seeder
```

A ticket Bob edits (other file, later expiry) gives a completely different
HMAC, so his key no longer matches and Alice denies it. A ticket for Carol
is useless at Alice because Carol's peer key is different. A removed member
gets no new tickets and loses access within 300 s.

The seeder does not compare the ticket's user field with anything, so
whoever holds both the ticket and its key can use it until it expires.

### 6.5 What the downloader does with each reply

| Reply | `TransferResult` | Next step |
| --- | --- | --- |
| no connection / broken | NetworkFailure | try the next holder |
| `60|unavailable` | Unavailable | try the next holder |
| `60|denied` or a `30` that won't decrypt | AuthenticationFailure | try the next holder |
| `30`, but SHA-256 differs from the tracker's piece hash | IntegrityFailure | counted, try the next holder |
| `30`, SHA-256 matches | Success | write the piece to `.part` |

---

## 7. One whole download

Bob types `download_file demo notes.txt ./out`. For this walk-through
assume the file is 8 MiB, so 4 pieces of 2 MiB. Alice (:7001) has all 4 pieces;
Carol (:7003) has pieces 1 and 2.

```text
Bob                         tracker                Alice :7001         Carol :7003
 |                             |                       |                   |
 | 1  [HS] download_file ----->|                       |                   |
 |    <---- META ... A/t/kA,C/t/kC                     |                   |
 |    prints "OK download started", worker thread starts                   |
 |                             |                       |                   |
 | 2  open ./out.part; keep pieces whose SHA-256 already matches (resume)    |
 |                             |                       |                   |
 | 3  --- 21 BITMAP (kA) ------------------------------>|                   |
 |    <-- 30 [01 01 01 01] -----------------------------|                   |
 |    --- 21 BITMAP (kC) -------------------------------------------------->|
 |    <-- 30 [00 01 01 00] --------------------------------------------------|
 |    rarity [1,2,2,1] -> order 0,3,1,2 (rarest first)                     |
 |                             |                       |                   |
 | 4  [HS] upload_file ... --->|  bob is now a seeder too (partial)        |
 |    <---- OK file shared ----|                       |                   |
 |                             |                       |                   |
 | 5  min(16 threads, 4 pieces) = 4 threads (not limited by seeders)       |
 |    --- 21 GET 0 (kA) ---------------------------->|  only Alice has 0   |
 |    <-- 30 piece 0 --------------------------------|                     |
 |    --- 21 GET 3 (kA) ---------------------------->|  only Alice has 3   |
 |    <-- 30 piece 3 --------------------------------|                     |
 |    --- 21 GET 1 (kC) ------------------------------------------------->|  1 % 2 -> Carol
 |    <-- 30 piece 1 -----------------------------------------------------|
 |    --- 21 GET 2 (kA) ---------------------------->|  2 % 2 -> Alice     |
 |    <-- 30 piece 2 --------------------------------|                     |
 |    each verified piece -> .part, and Bob's PeerServer can serve it     |
 |                             |                       |                   |
 | *  if a ticket expires within 60 s:                |                   |
 |    [HS] download_file ----->| fresh tickets          |                   |
 |    <---- META ... ----------| swapped in per seeder by ip:port          |
 |                             |                       |                   |
 | 6  whole-file SHA-256 matches? rename out.part -> out|                   |
 |    [HS] upload_file ... --->|  bob is now a full seeder                 |
 |    <---- OK file shared ----|                       |                   |
```

Each piece is tried on every seeder that has it, 3 passes, with a 200 ms
pause after each pass. If it still fails, the download ends as
`[F] ... reason="one or more pieces could not be reconstructed"`.
`cancel_download` keeps the `.part` file so a later download resumes.

---

## 8. Your questions, answered

**How does the tracker know how long a message is?**
Every message, plaintext or encrypted, starts with a 4-byte big-endian
length (section 2). The tracker reads 4 bytes, then exactly that many more.

**Is the HELLO sent directly? How does the tracker know how much to read?**
Yes, the HELLO is plaintext. There is no key yet, and nothing in it is
secret. It is still framed: the client sends `00 00 00 72` and then the 114
HELLO bytes, so the tracker knows to read 114 bytes.

**How does the tracker know whether a message is encrypted?**
By position, not by a marker. On every connection the order is fixed:
frame 1 = client HELLO (plaintext), frame 2 = tracker HELLO (plaintext),
frame 3 = request (encrypted), frame 4 = reply (encrypted). If someone sends
plaintext where frame 3 should be, the GCM check fails and the tracker drops
it (`no request received`).

**How is the ticket validated?**
By the seeder, with no call to the tracker (6.4). The seeder recomputes the
ticket's key from its own secret peer key. If Bob's frame decrypts with that
key, only the tracker could have given Bob the key, so the ticket is genuine.
Then it checks the expiry, the time inside the request, and that it shares
that file.

**Why a separate (ticket) key when there is already a session key?**
They protect different links:

```text
             session key                         ticket (request) key
 between     one client <-> tracker               downloader <-> one seeder
 made by     X25519 handshake                     tracker: HMAC(seeder peer key, ticket)
 lives       one TCP connection, then erased      until the ticket expires (300 s)
 known by    that client and the tracker          tracker, the downloader, that seeder
```

Bob's session key is shared only with the tracker, and it is gone as soon as
the `download_file` connection closes. Alice never knew it and can't learn
it. So Bob and Alice need a key that both of them have and that the tracker
vouches for, without the tracker being online for every piece. The ticket
key is exactly that.

**Do session ids survive multiple requests?**
Mind the two "sessions":

- **Session id** (the number from `login`, like `8312093445127730114`): yes.
  It lives in the tracker's memory and in `TrackerClient::session_`, and is
  sent on every request, each on its own connection, until `logout` or a
  tracker restart (the state is in memory only).
- **Session key** (the AES key from the handshake): no. It exists for one
  connection, so one command, and is then erased. The next command does a new
  handshake and gets a new key.

So `list_groups` and `list_files` are two connections, two handshakes and
two keys, but they carry the same session id, which is how the tracker knows
both come from Alice.

**Why is there a nonce in the header?**
There are three kinds:

1. HELLO nonces (16 bytes): make each handshake transcript, and so each
   tracker signature and session key, unique.
2. GCM nonces (12 bytes, in front of every encrypted frame and in every
   `21`/`30` frame): AES-GCM needs a fresh nonce for each message under a
   key, and reusing one breaks both secrecy and integrity. The receiver needs
   it to decrypt, so it travels with the message. It isn't secret.
3. The request nonce inside the `30` reply's AAD: it binds the reply to its
   request, so an old reply can't be replayed as the answer to a new request.

# Technical report

## Scope

Torrent Atlas implements tracker and peer workflows with a single tracker and direct encrypted peer transfer. File bytes never pass through the tracker.

## Tracker and persistence

The tracker answers every command from an in-memory `TrackerState`. Commands that change state run one at a time; after each one the whole state is serialized and saved with a temporary file, fsync and rename, so a crash leaves the old or the new state and an acknowledged change is never lost. Only the serialized state reaches the disk, never the commands themselves, so passwords exist only in memory and are stored as PBKDF2 hashes.

Rewriting the whole state per change is deliberately simple; the metadata is kilobytes. A large deployment would move to a journal or an embedded database.

## Access to files

There is no long-lived per-file key. Each running client makes a random 256-bit peer key that only it and the tracker know. When a member asks for a file, the tracker issues one ticket per seeder, naming the user, group, file and an expiry five minutes ahead, with key HMAC-SHA256(peer key, ticket). Seeders recompute the key, so only tickets the tracker issued, unedited and unexpired, decrypt. Membership changes (`remove_member`, `leave_group`) stop new tickets immediately, and downloads renew their tickets shortly before they expire.

Seeders verify the ticket and decrypt the request before looking up the file, and reply `60|denied` to every request that fails, so a peer reveals nothing about which files it holds to someone without a valid ticket.

## Transfer engine

Files are divided into 512 KiB pieces. The tracker stores the full SHA-1, ordered piece hashes, and each seeder's endpoint and peer key. Downloaders validate metadata before using piece counts in allocation or arithmetic.

Peers exchange framed AES-256-GCM messages. Authenticated data binds each request to its ticket and each response to the request nonce. Each received piece must match its SHA-1 before it is committed. A final full-file SHA-1 check runs before the temporary file is renamed.

The scheduler collects peer bitmaps and uses deterministic rarest-first ordering. Parallel workers choose only peers advertising a piece, rotate the starting peer to spread work, and retry failures. Telemetry reports availability, measured throughput, successes, and failure categories without converting them into trust or reputation scores.

Resume manifests record immutable metadata, the temporary path, and a verified-piece bitmap; they hold no keys. A resumed download re-hashes every claimed piece. Verified partial pieces are immediately available through the peer service.

## Reliability and safety

- Length-prefixed frames cap allocation at 16 MiB.
- Endpoint and unsigned decimal parsing require full token consumption.
- Ports, hashes, peer keys, tickets, piece counts, and saved-state records are validated.
- TCP connect uses nonblocking `connect` plus a deadline and `SO_ERROR` verification.
- Sockets, files and OpenSSL objects are owned by RAII classes (`Socket`, `PieceFile`, `OpenSslPtr`).
- The client requests cancellation, joins download threads, and joins its peer service on normal exit.
- User-visible tracker collections and peer metrics are sorted for deterministic demonstrations.
- Passwords are PBKDF2-HMAC-SHA256 encoded with random salts, travel only inside the encrypted client channel, and are never logged or saved.

## Verification

CTest covers parser strictness, frame boundaries, SHA-1 vectors, cryptography, resume manifests, tracker commands and access control, member removal, ticket issue and checking (guessed keys, edited, stretched and expired tickets), identical peer rejections, tracker crash and restart durability, the absence of plaintext passwords on disk, handshake and replay attacks, and a complete encrypted client transfer. CI runs a release configuration and an AddressSanitizer/UndefinedBehaviorSanitizer configuration on Ubuntu.

## Known limits

One tracker is a single point of failure for logins and new downloads. Tickets already issued stay valid for up to five minutes after a member is removed. SHA-1 remains only for integrity compatibility.

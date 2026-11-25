# Ablation studies

We made design decisions (AES-GCM, SHA-1, hex frames, 512 KiB pieces, a thread
cap, rarest-first) without measuring them. This document turns each one off or
varies it, one at a time, on real downloads, and records what happened.

- Short version: **two decisions were hurting, one was hiding behind another,
  and the rest were justified.** The fixes are on `main`: downloads went from
  164 to 485 MB/s on loopback and from 100 to 381 MB/s with 5 ms latency.
- Graphs: `docs/ablations/graphs/*.png`. Raw rows: `docs/ablations/results/*.csv`.
  All tables: `docs/ablations/results/tables.md`. Shorter write-up: `docs/ablations/RESULTS.md`.

## 1. How the experiments were run

```text
 bench/run_bench.py <experiment>
        │  for each variant, for each of N repetitions:
        ▼
  start a fresh tracker ──▶ owner client uploads a random file
        │                    3 more clients download it, so 4 seeders hold it
        ▼
  a new member joins, starts the clock, runs "download file", stops the clock
  when the file appears, then compares it byte for byte with the source
        ▼
  one CSV row: seconds, MB/s, CPU seconds, bytes sent on the wire, intact?
```

| Setting | Value |
|---|---|
| Machine | MacBook, arm64, 8 cores, macOS; everything over loopback (127.0.0.1) |
| File | 64 MB of random bytes (`os.urandom`) |
| Seeders | 4 clients holding the whole file |
| Repetitions | 5 per variant (3 for the 5 ms runs); tables show the median |
| Wire bytes | `netstat -ib -I lo0` bytes sent, before and after the download |
| CPU | user+sys of every client process during the download, from `ps` (10 ms steps). Use it to compare variants, not as an absolute number |
| Correctness | every downloaded file compared with `cmp`; all runs in every table are intact |
| "5 ms latency" | each seeder waits 5 ms before answering each piece request. It models a nearby server (round-trip delay), not limited bandwidth or lost packets |

How each switch was made: an `ablation.hpp` header read environment variables
(for example `TORRENT_ABL_ENCRYPT=0`); with none set the program behaved exactly
as shipped. That code lives in commit `5fbae44` (branch `ablation/harness`); the
shipped code on `main` no longer contains the switches. To rerun the whole
study, check out that commit and run `bench/run_all.sh <python>`
(needs `matplotlib` for `bench/plot.py`).

## 2. Results at a glance

```text
 throughput, 64 MB, 4 seeders (MB/s)                loopback     5 ms latency
 before (SHA-1, hex, 512 KiB, threads capped)  |###..........     164           100
 base64 instead of hex                         |########......    422           158
 16 threads instead of 4                       |####..........     224           191
 base64 + 16 threads                           |##########....     521           316
 base64 + 16 threads + 2 MiB pieces            |##########....     504           395
 what is on main now                           |#########.....     485           381
```

| Decision | What we measured | Verdict |
|---|---|---|
| Hex on the wire | 2.6x slower, 4.6x the CPU, 1.5x the bytes sent vs base64 | **Wrong. Replaced with base64** |
| Threads = min(8, seeders) | 4 threads here: 164 MB/s. 16 threads: 222 MB/s | **Too low. Now up to 16, no seeder limit** |
| 512 KiB pieces | Flat on loopback; with latency 99 vs 139 MB/s at 2 MiB | **Too small for a real network. Now 2 MiB** |
| AES-256-GCM | about 2.5 % of throughput; it is also what rejects forged tickets | Justified, kept |
| Per-piece hash check | 0.6 % | Justified, kept |
| Whole-file hash check | 1.2 % | Justified, kept |
| SHA-1 vs SHA-256 | Same speed (about 2.6 GB/s each); SHA-256 has no known collision attacks | **Switched to SHA-256** |
| Rarest-first | No speed effect when every seeder has the whole file | Kept; its value is availability, not speed |

## 3. Experiment by experiment

### 3.1 Wire encoding: hex vs base64 (the big one)

Peer messages are text split on `|`, so the binary nonce, ciphertext and tag must
be turned into text. Hex writes each byte as 2 characters (2x the size). Base64
writes 3 bytes as 4 characters (1.33x).

| Variant | MB/s | CPU s | Wire MB |
|---|---|---|---|
| hex (shipped) | 165.5 | 1.29 | 135.0 |
| base64 | 381.7 | 0.27 | 90.1 |

Why such a gap: our `fromHex` ran `isxdigit` twice and `std::from_chars` for every
single byte, and appended one byte at a time, over 2x the data. Base64 now uses
OpenSSL's `EVP_EncodeBlock` / `EVP_DecodeBlock`, which are tuned for this. CPU
fell from 1.29 s to 0.27 s per download, so hex was about 4/5 of all the work.
(This explanation comes from reading the code and the measured gap, not from a
profiler. A direct `fromHex` vs `fromBase64` micro-benchmark is a possible follow-up.)

A third option exists: raw bytes with a length prefix and no text encoding, which
would send 64 MB for a 64 MB file. It was not tried (see section 6).

Graph: `docs/ablations/graphs/encoding.png`.

### 3.2 Encryption: AES-256-GCM on peer transfers

First run (with hex still in place): 164.7 MB/s encrypted, 166.3 plaintext, so
encryption looked free. That was misleading: hex was so slow it hid everything
else. Rerun with base64 to remove that cost:

| Variant | MB/s | CPU s |
|---|---|---|
| AES-GCM (shipped) | 419.1 | 0.28 |
| plaintext | 408.5 | 0.26 |

The real cost is a few percent, within run-to-run noise. Encryption also does a
job nothing else does: with it off, the integration test "a ticket with a guessed
key is accepted" fails, because nothing checks the ticket key any more.
**Keep it.**

### 3.3 Integrity checks: per-piece and whole-file hash

| Variant (base64 build) | MB/s |
|---|---|
| per-piece check on | 423.7 |
| per-piece check off | 421.0 |
| whole-file check on | 413.2 |
| whole-file check off | 408.1 |

Both cost about 1 % or less, and they catch different things: the per-piece check
stops a bad piece before it is written or passed on to others; the whole-file
check catches a damaged resume file the per-piece checks missed. **Keep both.**

### 3.4 SHA-1 vs SHA-256

SHA-1 is not used for security anywhere in the code: the handshake, tickets and
passwords use Ed25519, X25519, HMAC-SHA256, PBKDF2-SHA256 and AES-256-GCM. SHA-1
only checked pieces and files for corruption, and the tracker sends those hashes
over the encrypted channel. Still, SHA-256 is easier to defend, and it is free:

| Hash | 64 KiB | 512 KiB | 2 MiB blocks |
|---|---|---|---|
| SHA-1 | 2,517 MB/s | 2,619 MB/s | 2,624 MB/s |
| SHA-256 | 2,631 MB/s | 2,643 MB/s | 2,654 MB/s |
| SHA-512 | 1,546 MB/s | 1,549 MB/s | 1,555 MB/s |

This was a hashing-only OpenSSL micro-benchmark on this Mac, not a full download.
Apple chips have hardware instructions for both SHA-1 and SHA-256. On a CPU
without them, SHA-1 is typically 1.5 to 2x faster, so the tie is specific to this
machine. The download needs under 0.5 GB/s of hashing, so either is far from the
bottleneck. **Switched to SHA-256.**

### 3.5 Thread count

The shipped code used min(8, number of seeders) threads. Here that was 4. Tested
with the thread count forced, even above the seeder count:

| Threads | Loopback MB/s | CPU s | 5 ms latency MB/s |
|---|---|---|---|
| 1 | 52.4 | 1.22 | 30.3 |
| 2 | 91.3 | 1.25 | 55.2 |
| 4 (shipped here) | 162.9 | 1.30 | 99.0 |
| 8 | 219.0 | 1.57 | 161.6 |
| 16 | 221.7 | 1.59 | 190.6 |
| 32 | 224.7 | 1.58 | 187.5 |

```text
 MB/s  (loopback)
 225 |                    ●───────●───────●
 160 |            ●
  90 |     ●
  50 | ●
     +----+-----+-----+-----+-----+-----+--
       1     2     4     8    16    32   threads
```

Gains flatten near 8 on loopback and near 16 with latency, while CPU keeps
rising. A seeder can serve several pieces at once, so tying the thread count to
the number of seeders was a mistake. **Now up to 16.**

### 3.6 Piece size

| Piece size | Loopback MB/s | 5 ms latency MB/s |
|---|---|---|
| 64 KiB | 144.2 | 26.7 |
| 128 KiB | 148.2 | 47.3 |
| 256 KiB | 155.1 | 74.1 |
| 512 KiB (shipped) | 162.1 | 98.6 |
| 1 MiB | 163.4 | 120.8 |
| 2 MiB | 156.5 | 139.4 |
| 4 MiB | 165.2 | 143.3 |

On loopback the curve is nearly flat. With latency it matters a lot, because each
piece costs one request and one reply, so small pieces pay the delay more times.
The trade-off: a corrupt or lost piece costs more to refetch, and resume works in
bigger steps. **Chose 2 MiB** (about 97 % of the 4 MiB result, with a smaller
retry cost). Note the 5 ms delay is a modelling choice, so treat the exact
numbers as a trend.

### 3.7 Piece selection

| Variant | MB/s |
|---|---|
| rarest-first (shipped) | 160.4 |
| sequential | 163.8 |
| random | 162.4 |

No difference, as expected: all four seeders held the whole file, so no piece is
"rare". Rarest-first exists to keep every piece available when seeders hold
different parts, which this test does not stress. **Do not claim it makes
downloads faster.** Kept because it is the standard way to keep the swarm healthy.

### 3.8 The fixes together

| Config | Loopback MB/s | 5 ms latency MB/s |
|---|---|---|
| before | 163.9 | 100.2 |
| base64 only | 422.5 | 158.4 |
| 16 threads only | 224.5 | 191.4 |
| base64 + 16 threads | 520.9 | 315.7 |
| base64 + 16 threads + 2 MiB pieces | 504.4 | 395.2 |

The gains stack, and 2 MiB pieces only pay off with latency (+25 %).

## 4. What shipped, measured again

After SHA-256, base64, 16 threads and 2 MiB pieces were applied to the real code
(commit `ba1aaee`), the same benchmark gave:

| Build | Loopback | 5 ms latency | CPU s | Wire MB |
|---|---|---|---|---|
| before | 164 MB/s | 100 MB/s | 1.31 | 135 |
| after | 485 MB/s | 381 MB/s | 0.35 | 90 |

3.0x faster on loopback, 3.8x with latency, and all 8 test programs pass. The
5 ms run used a scratch copy with the delay switch added; the switch is not in
the shipped code.

One bug showed up on the way: the seeder bound its reply to the request nonce
using the nonce as it arrived on the wire, while the client used it as hex. Both
were hex before, so it worked; switching the wire to base64 made `peer_access_tests`
fail until the seeder used `toHex` of the decoded nonce. Worth remembering as a
reminder that the tests catch this kind of protocol change.

## 5. Interview cheat sheet

- **"Why base64?"** The text frame is split on `|`, so binary must become text.
  Hex is 2x size and our decoder was slow; base64 is 1.33x and uses OpenSSL's tuned
  decoder. Measured 2.6x faster, 4.6x less CPU.
- **"Does encryption slow it down?"** About 2.5 % on this machine, and it is the
  thing that rejects forged tickets. Hex first hid this cost, which is why we
  re-measured after removing hex.
- **"SHA-1 or SHA-256?"** Same speed here. SHA-1 was never used for security, but
  SHA-256 has no known collision attacks, so it is simpler to defend.
- **"Why 16 threads / 2 MiB pieces?"** Throughput stops rising near 8 to 16
  threads while CPU keeps growing; bigger pieces cut the number of request round
  trips, which matters once the network has latency.
- **"Does rarest-first make it faster?"** No, not in this test. It keeps rare
  pieces available.
- **"How do you know it is correct?"** Every benchmark download was compared byte
  for byte with its source, and the 8 CTest programs pass.

## 6. Limits and what is not tested

- One machine, loopback only. The 5 ms delay is latency only: no bandwidth limit,
  no packet loss, no congestion. A network shaper such as macOS `dnctl` and
  `pfctl` would be a better test.
- AES and SHA are hardware accelerated on this CPU. Older or smaller CPUs would
  show higher costs for encryption and hashing.
- Differences under about 3 % are within noise (min-max ranges are in the CSVs;
  a few runs varied by 20 % or more, for example `base64 only` ranged 352 to 441).
- Rarest-first was not tested with seeders that hold different parts of the file,
  or with a seeder dropping out mid-download.
- Raw length-prefixed frames (no text encoding) would send 64 MB for 64 MB and
  save the base64 work, but were not tried.
- The tracker, login and group commands were not benchmarked; only the download
  path was.
- Piece size changes the stored hash list and resume granularity; old `.part`
  files and metadata made with 512 KiB / SHA-1 do not work with the new build.

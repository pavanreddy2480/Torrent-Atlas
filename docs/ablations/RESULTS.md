# Ablation results

Every design decision was switched off (or varied) one at a time, everything
else left as shipped. Raw rows: `results/*.csv`. Graphs: `graphs/*.png`.
All tables: `results/tables.md`. Rerun with `bench/run_all.sh`.

**Setup.** MacBook, 8 cores, loopback only. One tracker, 4 seeders, one fresh
member downloading a random 64 MB file (5 runs per variant, median shown;
3 runs for the 5 ms runs). "5 ms" adds a 5 ms wait to every seeder reply to
mimic a network with latency; plain runs have none. Every downloaded file was
compared byte for byte with the source (`intact` in the CSVs, all passed).
CPU is user+sys of all client processes during the download, from `ps`
(10 ms resolution), so use it for comparing variants, not as an absolute.

## Headline

```
 throughput, 64 MB, 4 seeders (MB/s)               loopback      5 ms latency
 shipped design                  |#######.......      164            100
 base64 instead of hex           |##################  422            158
 16 threads instead of 4         |#########..........  224            191
 base64 + 16 threads             |#######################  521        316
 base64 + 16 threads + 2 MiB     |######################  504        395
```

Two of our decisions were hurting, and one looks fine but was hiding the real cost.

## Findings, one per decision

| Decision | Verdict | Evidence |
|---|---|---|
| Hex on the wire | **Wrong, change it.** | Hex costs 2.6x throughput and 4.6x CPU vs base64 (164 vs 422 MB/s; 1.31 s vs 0.28 s CPU), and sends 135 MB instead of 90 MB for a 64 MB file. Cause: `fromHex` runs `isxdigit` + `from_chars` per byte, which dominates everything else. Raw binary framing would send 67 MB, the minimum. |
| AES-256-GCM on peer transfers | **Justified.** | With hex in the way it looked free (164 vs 166 MB/s). With hex out of the way the true cost is about 2.5 % (419 vs 409 MB/s). It is also what rejects forged tickets: with encryption off, the integration test's "ticket with a guessed key" is accepted. |
| Per-piece SHA-1 | **Justified.** | Cost 0.6 % (424 vs 421 MB/s), and it is the only check that catches a corrupt piece before it is written and seeded onward. |
| Whole-file SHA-1 | **Cheap, keep.** | Cost 1.2 % (413 vs 408 MB/s). It catches a bad resume file that per-piece checks cannot. |
| Threads = min(8, seeders) | **Too low.** | With 4 seeders we ran 4 threads (163 MB/s). 8 threads gave 219, 16 gave 222, 32 gave 225: gains stop near 8-16, then CPU rises. With 5 ms latency the gap is bigger: 99 vs 162 (8) vs 191 (16). The cap by seeder count is the mistake; one seeder can serve several pieces at once. |
| 512 KiB pieces | **Fine on loopback, small for real networks.** | Loopback: 144 (64 KiB) to 165 (4 MiB) MB/s, a flat curve. With 5 ms latency: 27 (64 KiB), 99 (512 KiB), 143 (4 MiB). Each piece is one request round trip, so bigger pieces pay latency less often. Trade-off: a corrupt piece wastes more to refetch. 1-2 MiB is the sweet spot. |
| Rarest-first | **No speed effect here (160 vs 164 vs 162 MB/s).** | All seeders held the whole file, so there is nothing "rare" to prefer. Its value is availability when seeders hold different parts, which this test does not stress. Don't claim a speed benefit in the interview. |

## What combining the fixes gives

| Config | Loopback MB/s | 5 ms latency MB/s |
|---|---|---|
| shipped | 164 | 100 |
| + base64 | 422 | 158 |
| + 16 threads | 224 | 191 |
| + base64 + 16 threads | 521 | 316 |
| + base64 + 16 threads + 2 MiB pieces | 504 | 395 |

On loopback the 2 MiB change doesn't matter; under latency it adds 25 %.

## Limits (say these before an interviewer does)

- Loopback is one machine; real networks have bandwidth limits and loss. The
  5 ms delay is a crude latency stand-in, not a network emulator.
- Rarest-first and seeder dropout were only tested for speed, not for the
  partial-seeder case. That still needs its own experiment.
- The encryption and hash costs are small partly because OpenSSL uses
  hardware AES and SHA on this CPU; an older machine would show more.
- Small differences (about 3 % or less) are within run-to-run noise.

## Suggested decisions

1. Replace hex with base64 or length-prefixed raw bytes for piece data (biggest win).
2. Do not cap threads by seeder count; use 8-16.
3. Move to 1-2 MiB pieces.
4. Keep AES-GCM and both SHA-1 checks.
5. Run the partial-seeder rarest-first experiment next.

## Applied (branch `ablation/apply-findings`)

The fixes are now in the code: SHA-256 for piece and file hashes, base64 on
peer frames, up to 16 download threads (no longer capped by seeder count) and
2 MiB pieces. AES-GCM and both hash checks stay. Same setup as above (64 MB,
4 seeders); raw rows in `results/after_apply*.csv`.

| Build | Loopback MB/s | 5 ms latency MB/s | CPU s | wire MB |
|---|---|---|---|---|
| before (shipped, SHA-1, hex) | 164 | 100 | 1.31 | 135 |
| after (this branch) | 485 | 381 | 0.35 | 90 |

That is 3.0x faster on loopback and 3.8x with latency, with the same 8/8 tests
passing and every downloaded file intact. The 5 ms run used a scratch copy of
this branch with the delay switch added; the switch is not in the shipped code.
Moving from SHA-1 to SHA-256 did not show up in the numbers (hashing both runs
at about 2.6 GB/s on this Mac), and the files stay byte-identical on download.

"""Runs an ablation experiment and appends rows to a CSV.

  python3 bench/run_bench.py encryption --reps 5 --size-mb 64 --seeders 2
"""
import argparse, csv, os, statistics, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Cluster, ROOT

# experiment -> list of (label, env overrides). The first label is the shipped design.
EXPERIMENTS = {
    "encryption": [("aes-gcm (shipped)", {}), ("plaintext", {"TORRENT_ABL_ENCRYPT": 0})],
    "encoding": [("hex (shipped)", {}), ("base64", {"TORRENT_ABL_ENCODING": "base64"})],
    "piece_verify": [("sha1 per piece (shipped)", {}), ("no piece check", {"TORRENT_ABL_PIECE_VERIFY": 0})],
    "final_verify": [("full-file sha1 (shipped)", {}), ("no final check", {"TORRENT_ABL_FINAL_VERIFY": 0})],
    "threads": [(f"{n} threads", {"TORRENT_ABL_THREADS": n}) for n in (1, 2, 4, 8, 16, 32)],
    "piece_size": [(f"{n // 1024} KiB", {"TORRENT_ABL_PIECE_SIZE": n})
                   for n in (64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 4 << 20)],
    "combined": [("shipped", {}), ("base64 only", {"TORRENT_ABL_ENCODING": "base64"}),
                 ("threads=16 only", {"TORRENT_ABL_THREADS": 16}),
                 ("base64 + 16 threads", {"TORRENT_ABL_ENCODING": "base64", "TORRENT_ABL_THREADS": 16}),
                 ("base64 + 16 threads + 2 MiB pieces", {"TORRENT_ABL_ENCODING": "base64", "TORRENT_ABL_THREADS": 16, "TORRENT_ABL_PIECE_SIZE": 2 << 20})],
    "after": [("current build", {})],
    "selection": [("rarest-first (shipped)", {}), ("sequential", {"TORRENT_ABL_SELECTION": "sequential"}),
                  ("random", {"TORRENT_ABL_SELECTION": "random"})],
}


def source_file(size_mb):
    path = f"/tmp/abl-source-{size_mb}mb.bin"
    if not os.path.exists(path) or os.path.getsize(path) != size_mb << 20:
        with open(path, "wb") as f:
            f.write(os.urandom(size_mb << 20))
    return path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("experiment", choices=sorted(EXPERIMENTS))
    p.add_argument("--reps", type=int, default=5)
    p.add_argument("--size-mb", type=int, default=64)
    p.add_argument("--seeders", type=int, default=2)
    p.add_argument("--base", default="", help="extra env, e.g. TORRENT_ABL_DELAY_MS=5")
    p.add_argument("--tag", default="")
    p.add_argument("--out", default=os.path.join(ROOT, "docs", "ablations", "results"))
    a = p.parse_args()
    base = dict(kv.split("=") for kv in a.base.split(",") if kv)
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"{a.experiment}{a.tag}.csv")
    src = source_file(a.size_mb)
    fields = ["experiment", "variant", "rep", "seeders", "size_mb", "seconds", "mb_per_s",
              "cpu_seconds", "wire_mb", "completed", "intact"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        for label, env in EXPERIMENTS[a.experiment]:
            rows = []
            for rep in range(a.reps):
                cluster = Cluster({**base, **env}, a.seeders, a.size_mb << 20, src)
                try:
                    m = cluster.measure()
                finally:
                    cluster.close()
                row = {"experiment": a.experiment, "variant": label, "rep": rep, "seeders": a.seeders,
                       "size_mb": a.size_mb, **{k: round(v, 4) for k, v in m.items()}}
                w.writerow(row); f.flush(); rows.append(row)
            med = statistics.median(r["mb_per_s"] for r in rows)
            print(f"{label:28s} median {med:8.1f} MB/s  cpu {statistics.median(r['cpu_seconds'] for r in rows):6.2f}s"
                  f"  wire {statistics.median(r['wire_mb'] for r in rows):7.1f} MB  ok={sum(r['intact'] for r in rows)}/{len(rows)}",
                  flush=True)
    print("wrote", path)


main()

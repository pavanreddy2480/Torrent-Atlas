#!/bin/sh
# Runs every ablation experiment. Usage: bench/run_all.sh <python>
PY=${1:-python3}
cd "$(dirname "$0")/.."
for e in encryption encoding piece_verify final_verify threads piece_size selection; do
  echo "== $e (loopback)"; $PY bench/run_bench.py $e --reps 5 --size-mb 64 --seeders 4
done
for e in threads piece_size; do
  echo "== $e (5 ms per request)"; $PY bench/run_bench.py $e --reps 3 --size-mb 64 --seeders 4 --base TORRENT_ABL_DELAY_MS=5 --tag _wan5ms
done

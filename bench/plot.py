"""Turns docs/ablations/results/*.csv into PNG graphs and a markdown table file."""
import csv, glob, os, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "docs", "ablations", "results")
OUT = os.path.join(ROOT, "docs", "ablations", "graphs")
os.makedirs(OUT, exist_ok=True)
tables = []

for path in sorted(glob.glob(os.path.join(RES, "*.csv"))):
    name = os.path.basename(path)[:-4]
    rows = list(csv.DictReader(open(path)))
    variants = list(dict.fromkeys(r["variant"] for r in rows))
    def col(v, key): return [float(r[key]) for r in rows if r["variant"] == v]
    med = [statistics.median(col(v, "mb_per_s")) for v in variants]
    lo = [m - min(col(v, "mb_per_s")) for v, m in zip(variants, med)]
    hi = [max(col(v, "mb_per_s")) - m for v, m in zip(variants, med)]
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))
    colors = ["#4c72b0" if i == 0 else "#dd8452" for i in range(len(variants))]
    if name.startswith(("threads", "piece_size")): colors = ["#4c72b0"] * len(variants)
    axes[0].bar(variants, med, yerr=[lo, hi], color=colors, capsize=3)
    axes[0].set_title("Throughput (MB/s, higher is better)")
    axes[1].bar(variants, [statistics.median(col(v, "cpu_seconds")) for v in variants], color=colors)
    axes[1].set_title("CPU seconds, all processes (lower is better)")
    axes[2].bar(variants, [statistics.median(col(v, "wire_mb")) for v in variants], color=colors)
    axes[2].set_title("Bytes sent on the wire (MB)")
    for ax in axes: ax.tick_params(axis="x", rotation=30, labelsize=8)
    r0 = rows[0]
    fig.suptitle(f"{name}: {r0['size_mb']} MB file, {r0['seeders']} seeders, median of {len(col(variants[0], 'seconds'))} runs")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, f"{name}.png"), dpi=130)
    plt.close(fig)
    t = [f"### {name}", "", "| variant | MB/s (median) | min-max | CPU s | wire MB | intact |", "|---|---|---|---|---|---|"]
    for v, m in zip(variants, med):
        t.append(f"| {v} | {m:.1f} | {min(col(v,'mb_per_s')):.0f}-{max(col(v,'mb_per_s')):.0f} | "
                 f"{statistics.median(col(v,'cpu_seconds')):.2f} | {statistics.median(col(v,'wire_mb')):.1f} | "
                 f"{int(sum(col(v,'intact')))}/{len(col(v,'intact'))} |")
    tables.append("\n".join(t))

open(os.path.join(RES, "tables.md"), "w").write("\n\n".join(tables) + "\n")
print("graphs in", OUT)

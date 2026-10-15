#!/bin/zsh
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

ROOT="${1:-$PWD}"
RUNS="${RUNS:-5}"
THREADS="${RAYON_NUM_THREADS:-1}"
M="${M:-3}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$ROOT/brief18q-tplus1-$STAMP}"

cd "$ROOT"
export RAYON_NUM_THREADS="$THREADS"
mkdir -p "$OUT"

BASE_TARGET="$OUT/target-default"
PLUS_TARGET="$OUT/target-tplus1"

echo "==> Build default random-pair benchmark"
CARGO_TARGET_DIR="$BASE_TARGET" \
  cargo build --release -p spark-binary --bin brief18q_tplus1_bench

echo "==> Build tplus1 benchmark"
CARGO_TARGET_DIR="$PLUS_TARGET" \
  cargo build --release -p spark-binary --features tplus1 --bin brief18q_tplus1_bench

BASE_BIN="$BASE_TARGET/release/brief18q_tplus1_bench"
PLUS_BIN="$PLUS_TARGET/release/brief18q_tplus1_bench"

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=$(git rev-parse HEAD)"
  echo "branch=$(git rev-parse --abbrev-ref HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  echo "runs=$RUNS"
  echo "threads=$THREADS"
  echo "commit_every=$M"
} | tee "$OUT/environment.txt"

for n in 16 18 20; do
  for mode in baseline tplus1; do
    if [[ "$mode" == "baseline" ]]; then
      BIN="$BASE_BIN"
    else
      BIN="$PLUS_BIN"
    fi
    for i in $(seq 1 "$RUNS"); do
      echo "==> n=$n mode=$mode run=$i/$RUNS"
      /usr/bin/time -l "$BIN" "$n" "$M" \
        >"$OUT/n${n}-${mode}-run${i}.txt" \
        2>"$OUT/n${n}-${mode}-run${i}.time"
    done
  done
done

python3 - "$OUT" <<'PY'
import csv, re, statistics, sys
from pathlib import Path

out = Path(sys.argv[1])
rows = []

def parse_kv(path):
    d = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d

for n in (16,18,20):
    for mode in ("baseline","tplus1"):
        runs = [parse_kv(p) for p in sorted(out.glob(f"n{n}-{mode}-run*.txt"))]
        if not runs:
            raise SystemExit(f"missing runs n={n} mode={mode}")
        rss = []
        for p in sorted(out.glob(f"n{n}-{mode}-run*.time")):
            m = re.search(r"(\d+)\s+maximum resident set size", p.read_text())
            if m:
                rss.append(int(m.group(1)))

        def med(key):
            return statistics.median(float(r[key]) for r in runs)

        proof_values = {int(r["proof_bytes"]) for r in runs}
        if len(proof_values) != 1:
            raise SystemExit(f"proof size changed across repeated runs: n={n} mode={mode}")

        rows.append({
            "n": n,
            "gates": runs[0]["gate_family"],
            "setup_ms": f"{med('setup_ms'):.3f}",
            "encode_ms": f"{med('encode_ms'):.3f}",
            "commit_ms": f"{med('commit_ms'):.3f}",
            "fold_ms": f"{med('fold_ms'):.3f}",
            "prove_ms": f"{med('prover_ms'):.3f}",
            "verify_ms": f"{med('verify_ms'):.3f}",
            "proof_bytes": next(iter(proof_values)),
            "rss_bytes": int(statistics.median(rss)) if rss else "",
            "s": runs[0]["s"],
            "verified": all(r.get("verified") == "true" for r in runs),
        })

# Hard requirement from Brief 18r: same proof bytes by gate family at each n.
for n in (16,18,20):
    rs = [r for r in rows if r["n"] == n]
    if len(rs) != 2:
        raise SystemExit(f"bad summary row count for n={n}")
    if rs[0]["proof_bytes"] != rs[1]["proof_bytes"]:
        print(
            f"ERROR: proof bytes differ at n={n}: "
            f"{rs[0]['proof_bytes']} vs {rs[1]['proof_bytes']}",
            file=sys.stderr,
        )
        raise SystemExit(2)

fields = [
    "n","gates","setup_ms","encode_ms","commit_ms","fold_ms",
    "prove_ms","verify_ms","proof_bytes","rss_bytes","s","verified"
]
with (out/"summary.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

header = (
    "| n | gates | setup ms | encode ms | commit ms | fold ms | prove ms | "
    "verify ms | proof bytes | RSS bytes |\n"
    "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
)
body = "".join(
    f"| {r['n']} | {r['gates']} | {r['setup_ms']} | {r['encode_ms']} | "
    f"{r['commit_ms']} | {r['fold_ms']} | {r['prove_ms']} | {r['verify_ms']} | "
    f"{r['proof_bytes']} | {r['rss_bytes']} |\n"
    for r in rows
)
(out/"summary.md").write_text(header + body)

print((out/"summary.md").read_text())
print(f"CSV={out/'summary.csv'}")
print(f"TABLE={out/'summary.md'}")
PY

echo "RESULT_DIR=$OUT"

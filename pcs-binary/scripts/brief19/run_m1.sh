#!/usr/bin/env bash
# Brief 19 on the reference machine (Apple M1): builds both layouts and runs
# (1) the commit micro-benchmark and (2) the interleaved end-to-end benchmark.
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel); cd "$ROOT"
OUT=${1:-$HOME/brief19_m1}; mkdir -p "$OUT"
cargo build --release -q -p spark-binary --bin brief19_block_leaves_bench --bin brief19_commit_microbench
cp target/release/brief19_block_leaves_bench "$OUT/bench_pair"
cp target/release/brief19_commit_microbench "$OUT/microbench"
cargo build --release -q -p spark-binary --features block-leaves --bin brief19_block_leaves_bench
cp target/release/brief19_block_leaves_bench "$OUT/bench_block"
S=pcs-binary/scripts/brief19
echo "variant,n,c,threads,commit_ms,root" > "$OUT/micro.csv"
for th in 1 8; do for n in 16 18 20; do for c in 2 3 4; do
  RAYON_NUM_THREADS=$th "$OUT/microbench" $n $c 20 >> "$OUT/micro.csv"
done; done; done
(cd "$OUT" && python3 "$ROOT/$S/summarize_micro.py" > micro_table.md)
bash $S/run_brief19_bench.sh "$OUT/bench_pair" "$OUT/bench_block" "$OUT/e2e.csv" 10 1 8
python3 $S/summarize.py "$OUT/e2e.csv" > "$OUT/e2e_table.md"
cat "$OUT/micro_table.md" "$OUT/e2e_table.md"

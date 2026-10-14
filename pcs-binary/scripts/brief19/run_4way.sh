#!/usr/bin/env bash
# Four-way interleaved benchmark: {random gates, (t,t+1) gates} x {pair leaves, block leaves},
# same commit, same machine, same session. random+pair is the v0.9.1-equivalent baseline.
# Usage: run_4way.sh [out_dir] [rounds]
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel); cd "$ROOT"
OUT=${1:-$HOME/brief19_4way}; ROUNDS=${2:-10}; mkdir -p "$OUT"
B=brief19_block_leaves_bench
build() { cargo build --release -q -p spark-binary --bin $B $1; cp target/release/$B "$OUT/$2"; }
build "--no-default-features" random_pair
build "--no-default-features --features block-leaves" random_block
build "" tplus1_pair
build "--features block-leaves" tplus1_block
CSV="$OUT/e2e_4way.csv"
echo "variant,n,c,threads,encode_ms,commit0_ms,fold_ms,commit_folds_ms,query_open_ms,grind_ms,prover_core_ms,prover_total_ms,verify_ms,proof_bytes,hash_calls,compressions" > "$CSV"
for th in 1 8; do for c in 3 4; do for r in $(seq 1 "$ROUNDS"); do
  for v in random_pair tplus1_pair random_block tplus1_block; do
    RAYON_NUM_THREADS=$th "$OUT/$v" 20 $c 2 1 >> "$CSV"
  done
done; done; done
python3 pcs-binary/scripts/brief19/summarize_4way.py "$CSV" | tee "$OUT/e2e_4way.md"

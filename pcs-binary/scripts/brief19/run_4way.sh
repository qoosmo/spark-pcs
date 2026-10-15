#!/usr/bin/env bash
# Four-way interleaved benchmark: {random gates, (t,t+1) gates} x {rc1 layout, v0.10 layout},
# same commit, same machine, same session. random+rc1 is the v0.9.1-equivalent baseline;
# (t,t+1)+v0.10 is the v0.10 release (group leaves, keyed hashing).
# Usage: run_4way.sh [out_dir] [rounds]
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel); cd "$ROOT"
OUT=${1:-$HOME/brief19_4way}; ROUNDS=${2:-10}; mkdir -p "$OUT"
B=brief19_block_leaves_bench
build() { cargo build --release -q -p spark-binary --bin $B $1; cp target/release/$B "$OUT/$2"; }
build "--no-default-features --features rc1-layout" random_rc1
build "--no-default-features" random_v10
build "--features rc1-layout" tplus1_rc1
build "" tplus1_v10
CSV="$OUT/e2e_4way.csv"
echo "variant,n,c,threads,encode_ms,commit0_ms,fold_ms,commit_folds_ms,query_open_ms,grind_ms,prover_core_ms,prover_total_ms,verify_ms,proof_bytes,hash_calls,compressions" > "$CSV"
for th in 1 8; do for c in 3 4; do for r in $(seq 1 "$ROUNDS"); do
  for v in random_rc1 tplus1_rc1 random_v10 tplus1_v10; do
    RAYON_NUM_THREADS=$th "$OUT/$v" 20 $c 2 1 >> "$CSV"
  done
done; done; done
python3 pcs-binary/scripts/brief19/summarize_4way.py "$CSV" | tee "$OUT/e2e_4way.md"

#!/usr/bin/env bash
# Brief 19 benchmark: interleaved pair-leaf vs block-leaf runs.
# Usage: run_brief19_bench.sh <bench_pair> <bench_block> <out.csv> [rounds] [threads...]
set -euo pipefail
P=$1; B=$2; OUT=$3; ROUNDS=${4:-10}; shift 4 || true
THREADS=${@:-1}
echo "variant,n,c,threads,encode_ms,commit0_ms,fold_ms,commit_folds_ms,query_open_ms,grind_ms,prover_core_ms,prover_total_ms,verify_ms,proof_bytes,hash_calls,compressions" > "$OUT"
for th in $THREADS; do
  for cfg in "16 3" "18 3" "20 3" "20 2" "20 4"; do
    set -- $cfg
    for r in $(seq 1 "$ROUNDS"); do
      RAYON_NUM_THREADS=$th "$P" "$1" "$2" 2 1 >> "$OUT"
      RAYON_NUM_THREADS=$th "$B" "$1" "$2" 2 1 >> "$OUT"
    done
  done
done
echo "wrote $OUT"

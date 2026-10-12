#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
ROOT="${ROOT:-$HOME/Downloads/spark-binary}"
TOTAL="${1:-16}"; MODE="${2:-}"; RUNS="${RUNS:-10}"; THREADS="${THREADS:-8}"
N="${N:-20}"; M="${M:-3}"
cd "$ROOT"
if [[ "$MODE" == "--reencode" ]]; then
  echo "LEGACY_REENCODE=EXPLICIT"
  echo "Frozen v0.8 low-memory re-encode is not the release default."
  exit 0
fi
cargo build --release --bin brief12_batch_bench >/dev/null
echo "POLICY=independent_batches_at_most_16"
echo "COMMON_POINT=NO"
r="$TOTAL"; b=0
while (( r>0 )); do
  t=$(( r>16 ? 16 : r )); b=$((b+1))
  echo "=== batch $b size=$t ==="
  RAYON_NUM_THREADS="$THREADS" target/release/brief12_batch_bench "$t" "$M" "$RUNS" "$N"
  r=$((r-t))
done

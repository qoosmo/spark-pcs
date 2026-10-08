#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-$HOME/Downloads/spark-binary}"
DST="${2:-$HOME/Downloads/spark-pcs}"
[[ -d "$SRC" ]] || { echo "missing source $SRC"; exit 2; }
[[ -d "$DST" ]] || { echo "missing target repo $DST"; exit 2; }
[[ -d "$DST/pcs" ]] || { echo "target lacks existing pcs/"; exit 2; }
[[ -d "$DST/experiments" ]] || { echo "target lacks existing experiments/"; exit 2; }

rm -rf "$DST/pcs-binary"
mkdir -p "$DST/pcs-binary" "$DST/research/brief13"
rsync -a \
  --exclude .git \
  --exclude target \
  --exclude 'brief12b-benchmarks' \
  --exclude 'freeze-v0.7' \
  --exclude 'freeze-v0.8' \
  "$SRC/" "$DST/pcs-binary/"

for f in \
  "$SRC/src/bin/brief13_partd.rs" \
  "$SRC/src/bin/brief13c_partd.rs" \
  "$SRC/research/brief13/partE_summary.tex" \
  "$SRC/research/brief13/partE_char2.rs"
do
  [[ -f "$f" ]] && cp "$f" "$DST/research/brief13/"
done

echo "prepared release tree; no commit or push performed"

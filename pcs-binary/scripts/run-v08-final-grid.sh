#!/bin/zsh
set -euo pipefail

ROOT="${1:-$HOME/Downloads/spark-binary}"
RUNS="${RUNS:-10}"
RUN_N22="${RUN_N22:-0}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$ROOT/freeze-v0.8/grid-$STAMP}"

mkdir -p "$OUT"
cd "$ROOT"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN_DIR="$TARGET_DIR/release"

echo "=== SPARK v0.8 FINAL GRID ===" | tee "$OUT/README.txt"
{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "release_source_commit=b8e80812856965bb8b7501e0459e58fc0fbbdab2"
  echo "release_source_dirty=false"
  echo "public_repo_commit=$(git rev-parse HEAD)"
  if [[ -z "$(git status --porcelain)" ]]; then
    echo "public_repo_dirty=false"
  else
    echo "public_repo_dirty=true"
  fi
  echo "branch=$(git rev-parse --abbrev-ref HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  sysctl -n machdep.cpu.brand_string 2>/dev/null | sed 's/^/cpu=/' || true
  sysctl -n hw.memsize 2>/dev/null | sed 's/^/memory_bytes=/' || true
  echo "RUSTFLAGS=${RUSTFLAGS:-}"
  echo "RUNS=$RUNS"
  echo "RUN_N22=$RUN_N22"
} | tee "$OUT/environment.txt"

cargo build --release --bin brief12_batch_bench --bin v08_setup_bench --bin spark-params

NS=(16 18 20)
if [[ "$RUN_N22" == "1" ]]; then
  NS+=(22)
fi

# One-time setup medians for each n.
for n in $NS; do
  echo "=== setup n=$n ==="
  "$BIN_DIR/v08_setup_bench" "$n" "$RUNS" | tee "$OUT/setup-n${n}.txt"
done

# Configurations required by Brief 14:
# single m=3, single m=4, batch t=16 m=3.
for threads in 1 8; do
  for n in $NS; do
    for spec in "1 3" "1 4" "16 3"; do
      set -- $=spec
      t="$1"; m="$2"
      name="n${n}-t${t}-m${m}-thr${threads}"
      echo "=== $name ==="
      {
        echo "release_source_commit=b8e80812856965bb8b7501e0459e58fc0fbbdab2"
        echo "release_source_dirty=false"
        echo "public_repo_commit=$(git rev-parse HEAD)"
        if [[ -z "$(git status --porcelain)" ]]; then
          echo "public_repo_dirty=false"
        else
          echo "public_repo_dirty=true"
        fi
        RAYON_NUM_THREADS="$threads" \
          /usr/bin/time -l \
          "$BIN_DIR/brief12_batch_bench" "$t" "$m" "$RUNS" "$n" \
          2> "$OUT/$name.time.txt"
      } > "$OUT/$name.txt"

      grep -q "^verified_runs=${RUNS}/${RUNS}$" "$OUT/$name.txt"
      grep -E '^(brief12b_|n=|delta_code=|fold_term_bits=|setup_ms=|encode_ms=|commit0_ms=|fold_ms=|commit_folds_ms=|grind_ms=|openings_ms=|prover_ms=|prover_per_poly_ms=|verify_ms=|verify_per_poly_ms=|proof_bytes=|proof_kib=|proof_per_poly_kib=|field_bytes=|hash_bytes=|peak_memory_estimate_|verified_runs=)' "$OUT/$name.txt"
      grep -E 'maximum resident set size' "$OUT/$name.time.txt" || true
    done
  done
done

python3 scripts/parse-v08-grid.py "$OUT"

echo
echo "=== COMPLETE ==="
echo "OUT=$OUT"
echo "CSV=$OUT/v08-final-grid.csv"
echo "LATEX=$OUT/v08-final-grid.tex"
echo "BREAKDOWN=$OUT/v08-final-grid-breakdown.tex"
echo
echo "Do not tag yet. Review the generated grid first."

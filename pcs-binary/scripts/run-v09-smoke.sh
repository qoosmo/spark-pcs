#!/bin/zsh
set -euo pipefail

ROOT="${1:-$HOME/Downloads/spark-pcs/pcs-binary}"
RUNS="${RUNS:-1}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$ROOT/v09-smoke-$STAMP}"

REPO="$(git -C "$ROOT" rev-parse --show-toplevel)"
RELEASE_SOURCE_COMMIT="$(git -C "$REPO" rev-parse '6162a25^{commit}')"

if git -C "$REPO" diff --quiet "$RELEASE_SOURCE_COMMIT" -- \
  pcs-binary/src/encode.rs \
  pcs-binary/src/transcript_v09.rs \
  pcs-binary/src/protocol_sparse_v06.rs \
  pcs-binary/src/protocol_batch_v12.rs
then
  RELEASE_SOURCE_DIRTY=false
else
  RELEASE_SOURCE_DIRTY=true
fi

PUBLIC_REPO_COMMIT="$(git -C "$REPO" rev-parse HEAD)"

if [[ -z "$(git -C "$REPO" status --porcelain)" ]]; then
  PUBLIC_REPO_DIRTY=false
else
  PUBLIC_REPO_DIRTY=true
fi

mkdir -p "$OUT"
cd "$ROOT"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/release/brief15_v09_smoke"

cargo build --release --bin brief15_v09_smoke

{
  echo "release_source_commit=$RELEASE_SOURCE_COMMIT"
  echo "release_source_dirty=$RELEASE_SOURCE_DIRTY"
  echo "public_repo_commit=$PUBLIC_REPO_COMMIT"
  echo "public_repo_dirty=$PUBLIC_REPO_DIRTY"
  echo "branch=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  sysctl -n machdep.cpu.brand_string 2>/dev/null | sed 's/^/cpu=/' || true
  sysctl -n hw.memsize 2>/dev/null | sed 's/^/memory_bytes=/' || true
  echo "RUNS=$RUNS"
  echo "RAYON_NUM_THREADS=1"
} | tee "$OUT/environment.txt"

for i in $(seq 1 "$RUNS"); do
  {
    echo "release_source_commit=$RELEASE_SOURCE_COMMIT"
    echo "release_source_dirty=$RELEASE_SOURCE_DIRTY"
    echo "public_repo_commit=$PUBLIC_REPO_COMMIT"
    echo "public_repo_dirty=$PUBLIC_REPO_DIRTY"
    echo "run=$i"
    RAYON_NUM_THREADS=1 "$BIN"
  } | tee "$OUT/run-$i.txt"
done

python3 - "$OUT" "$RUNS" <<'PY2'
import csv
import re
import statistics
import sys
from pathlib import Path

out = Path(sys.argv[1])
runs = int(sys.argv[2])

def parse(path):
    d = {}
    for line in path.read_text().splitlines():
        m = re.match(r'^([A-Za-z0-9_]+)=(.+)$', line)
        if m:
            d[m.group(1)] = m.group(2)
    return d

env = parse(out / "environment.txt")
results = [parse(out / f"run-{i}.txt") for i in range(1, runs + 1)]

prover = [float(r["prover_ms"]) for r in results]
verifier = [float(r["verifier_ms"]) for r in results]

r0 = results[0]

row = {
    "release_source_commit": env["release_source_commit"],
    "release_source_dirty": env["release_source_dirty"],
    "public_repo_commit": env["public_repo_commit"],
    "public_repo_dirty": env["public_repo_dirty"],
    "n": 20,
    "k": 2,
    "i0": 3,
    "m": 3,
    "g": 16,
    "s": r0["s"],
    "t": 1,
    "threads": 1,
    "runs": runs,
    "seed": r0["seed"],
    "setup_counter": r0["setup_counter"],
    "fold_term_bits": r0["fold_term_bits"],
    "query_term_bits": r0["query_term_bits"],
    "prover_ms": f"{statistics.median(prover):.3f}",
    "verifier_ms": f"{statistics.median(verifier):.3f}",
    "proof_bytes": r0["proof_bytes"],
    "proof_kib": r0["proof_kib"],
    "header_bytes": r0["header_bytes"],
    "wrapper_bytes": r0["wrapper_bytes"],
    "verified": r0["verified"],
}

with (out / "v09-smoke.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(row.keys()))
    w.writeheader()
    w.writerow(row)

with (out / "v09-smoke.txt").open("w") as f:
    for k, v in row.items():
        f.write(f"{k}={v}\n")

print(out / "v09-smoke.csv")
print(out / "v09-smoke.txt")
PY2

cat "$OUT/v09-smoke.txt"

echo "RESULT_DIR=$OUT"
echo "CSV=$OUT/v09-smoke.csv"

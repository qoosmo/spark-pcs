#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
ROOT="${1:-$HOME/Downloads/spark-binary}"
TAG="${2:-}"
OUT="${OUT:-$ROOT/freeze-v0.8}"
mkdir -p "$OUT"
cd "$ROOT"
{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=$(git rev-parse HEAD)"
  echo "branch=$(git rev-parse --abbrev-ref HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  sysctl -n machdep.cpu.brand_string 2>/dev/null | sed 's/^/cpu=/' || true
  sysctl -n hw.memsize 2>/dev/null | sed 's/^/memory_bytes=/' || true
  echo "RUSTFLAGS=${RUSTFLAGS:-}"
} | tee "$OUT/environment.txt"

cargo build --release
cargo test --release --bin spark-params
cargo run --release --bin spark-params -- \
  --n 20 --k 2 --i0 3 --g 16 --target 192 | tee "$OUT/params-n20.txt"

if [[ "$TAG" == "--tag" ]]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: dirty working tree; refusing to tag v0.8" >&2
    exit 2
  fi
  git tag -a v0.8 -m "SPARK v0.8 freeze"
  echo "tagged v0.8 at $(git rev-parse HEAD)"
else
  echo "not tagging; use --tag only after final benchmark commit is frozen"
fi

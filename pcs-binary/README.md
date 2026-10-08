# spark-binary

First executable prototype of SPARK matrix-gate folding over `GF(2^128)`.

## Goal

Measure the *whole* core PCS pipeline without FFTs:

1. multilinear gate encoding `u + t v`;
2. BLAKE3 Merkle commitment;
3. pairwise SPARK folds in characteristic two;
4. Merkle roots for intermediate layers.

This is intentionally a correctness/performance baseline. The field multiplier is portable Rust; the next optimization target is a CLMUL/GFNI backend.

## Field

`GF(2^128)` using

`x^128 + x^7 + x^2 + x + 1`.

Addition/subtraction are XOR.

SPARK gate:

```text
(u,v) -> (u + t0*v, u + t1*v)
```

Fold in characteristic two:

```text
lambda = (z+t0)/(t1+t0)
y      = w0 + lambda*(w1+w0)
```

## Build / test

```bash
cargo test --release
cargo run --release -- 16 2
```

Arguments are `n k [seed]`.

## Criterion microbenchmarks

```bash
cargo bench --bench field
cargo bench --bench encode
cargo bench --bench fold
```

## First end-to-end sweep

```bash
for n in 16 18 20; do
  cargo run --release -- $n 2 1
done
```

Start small: the portable multiplier is deliberately not yet architecture-optimized.

## What the timings mean

- `encode_ms`: SPARK gate-code encoding
- `commit0_ms`: Merkle root of the encoded word
- `fold_ms`: all field folding work
- `fold_commit_ms`: Merkle roots of intermediate folding layers
- `pcs_core_total_ms`: sum of the four above

Not yet included:

- authentication-path extraction / proof serialization
- verifier timing
- Fiat–Shamir transcript hashing
- comparison harness against Binius/BaseFold

Those are the next milestones after validating the binary algebra and replacing the scalar field multiplier.

## Parameters and security

The v0.8 binary implementation uses `GF(2^128)` for the base/gate field and
`GF(2^256)` for Fiat-Shamir fold challenges and folded layers. The default
configuration is `n=20, k=2, i0=3, g=16` with BLAKE3.

The Fiat-Shamir target is 192 bits under the current model
`128 + log2(Q)` with `Q <= 2^64` random-oracle queries. The checked setup
exhaustively verifies the `C3` prefix and supplies the certified distance used
by the security calculator. Grinding contributes `g=16` bits to the query
term.

Batch opening uses one query set for the whole batch, so the theorem-derived
query count `s` is independent of the number of polynomials `t`. The v0.8
operating point is `t=16, m=3`. For more than 16 polynomials, use independent
batches of 16 unless all evaluations must share one common point; in that case
use one common batch. The memory-saving re-encode path remains opt-in.

Reproduce the parameter calculation with:

```bash
cargo run --release --bin spark-params -- \
  --n 20 --k 2 --i0 3 --g 16 --target 192
```


## Brief 14 release closeout

Reproduce the final table:

```bash
cargo run --release -p spark-binary --bin bench -- --v08
```

Run the expensive checked-setup regression explicitly:

```bash
cargo test --release brief10_honest_i0_3_setup_passes -- --ignored --nocapture
```

For more than 16 polynomials, the release wrapper defaults to independent batches of at most 16:

```bash
./scripts/run-batch-v08.sh 32
```

Separate batches use separate challenges. If a common point is required, use a single batch. The historical re-encode route is explicit (`--reencode`).

Fiat-Shamir audit: `docs/fiat-shamir-v08-audit.md`.
Fair baseline: not done; the freeze machine is Apple M1, while Brief 14 requires x86/AVX2.

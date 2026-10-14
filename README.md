# SPARK: matrix-gate folding

A commitment scheme for multilinear polynomials. Folding with the verifier's challenges is both
the proximity test and the evaluation proof.

**Author:** Abdelali Mkhida ([Algorizk](https://algorizk.xyz)), ORCID 0009-0009-2101-9070

## Idea in one paragraph

Every node of a binary tree gets a $2\times2$ gate matrix, which is equivalent to two independent
random points $t^0, t^1$. A multilinear polynomial $F$ is encoded by evaluating it at the points the
tree generates, with $2^k$ independent copies for redundancy. The prover commits to this table.
The verifier sends challenges $z_1,\dots,z_n$, and the prover folds the table one variable at a
time by the gate rule. The last table is the constant $F(z_1,\dots,z_n)$. The verifier spot-checks
the gate rule along random root-to-leaf paths.

- No structured evaluation domain.
- Works over any field.
- The encoder only uses operations $u + t\,v$.

## Contents

| folder | what |
|---|---|
| `paper/` | full specification with proofs: `spark.tex`, `spark.pdf` |
| `pcs/` | Rust prototype: commit, prove, verify, Fiat–Shamir, Merkle; Goldilocks with a cubic extension |
| `experiments/` | Rust experiments behind the distance results (rank tests, MDS checks, obstructions) |
| `lean/` | formal proofs (in progress) |

## Main results (see `paper/spark.pdf`)

- **Code.** Per-node random gates give a linear code. The generic code is MDS (Thm 3.16).
- **Distance.**
  - One-layer bound (Thm 3.10).
  - Rank-saturation bound (Thm 3.14).
  - Checked-setup bound (Thm 3.19).
  - Zero decomposition and coincidence obstruction.
- **Folding.** Preserves proximity and agreement sets (Lemma 6.2).
- **Soundness.** Theorem 6.4:
  $\Pr[\text{accept a false claim}] \le n(N_1+1/\varepsilon)/|\mathbb{K}| + (1-\delta+n\varepsilon)^s$,
  with no loss in $n$ in the query term.

## Build

```sh
cargo test --release
cargo run --release -p spark-pcs --bin bench -- 16 5      # n = 16 variables, 2^5 copies
cargo run --release -p gatecode -- ident                  # algebraic identity checks
```

Experiment modes: `ident`, `bound`, `bound2`, `sweep`, `isd`, `sanity2`, `p1`, `p2`, `mdsx`, `coll`, `checked`, `vand`.


## v0.10 release

v0.10 combines two independent prover optimizations; soundness, `s=407` and the fields are unchanged.

- **Specialized gates** `(t,t+1)`: `a = u + t v`, `b = a + v`, fold coefficient `z + t`. Encoding cost halves.
- **Keyed group leaves**: one Merkle leaf per query group, BLAKE3 keyed mode; an internal node is one compression.

Profiles (`n=20, k=2, i0=3, g=16`, 192-bit target):

| profile | `commit_every` | proof (pinned) | use |
|---|---|---|---|
| `ParamsV10::compact()` | 3 | 591,562 B | smallest proof |
| `ParamsV10::fast()` | 4 | 647,522 B | fastest prover |

Four-way comparison, Apple M1, one thread, `n=20` (median of 20 interleaved runs):

| gates, leaves | prover `m=3` | prover `m=4` |
|---|---|---|
| random, pair (v0.9.1) | 1669 ms | 1567 ms |
| `(t,t+1)`, pair (rc1) | 1367 ms | 1305 ms |
| random, group | 1137 ms | 1001 ms |
| `(t,t+1)`, group | **882 ms** | **738 ms** |

Eight threads: `510 -> 323 ms` (`m=3`), `462 -> 176 ms` (`m=4`). The group rows used tagged leaves; keyed hashing (the v0.10 default) cuts commit time by another 22-30%.

Smoke: `cargo run --release -p spark-binary --bin v010_release_smoke`

## v0.9 release

SPARK v0.9 fixes the canonical Fiat–Shamir transcript and verifier parameter binding while leaving the encoder, folding rule, gate construction, Merkle construction, and query algorithm unchanged.

Release parameters:

- `F = GF(2^128)` with modulus `x^128 + x^7 + x^2 + x + 1`
- `K = F[y]/(y^2 + y + x^121)`
- public gate seed `5884642712365344205`
- setup counter `0` for `n=20, k=2, i0=3`
- `target_bits = 192`
- `s = 407`

See [`fiat-shamir-v09.md`](fiat-shamir-v09.md).

The verifier recomputes the query count from `(n,k,i0,g)` and the security target, and rejects any parameter set with fewer queries.

### v0.9 smoke

`RUNS=1 cargo run --release -p spark-binary --bin bench -- --v09`

Pinned result:

- proof: `590977` bytes
- header: `148` bytes
- wrapper: `153` bytes

## Status

- **Prototype.** Rayon-parallel prover, keyed group leaves (v0.10). Parameters use the rank-saturation bound.
- **In progress.**
  - Checked setup in the prototype.
  - Parallel prover.
  - Formal Fiat–Shamir analysis.
  - Lean proofs.
- **Open problems** (paper, §3 and §6): the level count in the distance bound, and soundness up to radius $\Delta/2$.

## License

Dual-licensed under MIT or Apache-2.0, at your option.

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

## Status

- **Prototype.** Single-threaded and unoptimised. Parameters currently use the rank-saturation bound.
- **In progress.**
  - Checked setup in the prototype.
  - Parallel prover.
  - Formal Fiat–Shamir analysis.
  - Lean proofs.
- **Open problems** (paper, §3 and §6): the level count in the distance bound, and soundness up to radius $\Delta/2$.

## License

Dual-licensed under MIT or Apache-2.0, at your option.

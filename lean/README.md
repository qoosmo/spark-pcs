# SPARK — Lean 4 formalization (first version)

Section-by-section formalization of the SPARK paper. Mathlib-based.

Build:
```
cd lean && lake exe cache get && lake build
```

| Paper section | Lean file | Status |
|---|---|---|
| 2 Gates | `SparkLean/Gates.lean` | v1: all lemmas stated and proved (parametrization, decomposition, uniqueness, collapse, gate rule, sum rule). The uniformity statement of the parametrization lemma is deferred to the probability layer. |
| 3 Gate code | `SparkLean/Code.lean` | v1: encoding, **closed form** $\mathrm{Enc}_n(F)(\omega)=F(r(\omega))$, prefix structure of the points, scalar compatibility, cost $T(n)=(n+1)2^{n+k}$, per-layer obstruction (support = all-ones paths). Next: weight count $2^k$, extension of scalars, rate-1. |
| 3 Distance: one-layer, rank saturation, augmentation, generic MDS, checked setup | `SparkLean/Distance.lean` | deterministic lemmas (augmentation) proved; probabilistic theorems stated |
| 4 Folding: fold, compatibility, contraction, line form, line proximity | `SparkLean/Fold.lean` | planned |
| 5–6 Protocol, completeness, soundness, schedules, batch opening | `SparkLean/Protocol.lean`, `SparkLean/Soundness.lean` | completeness proved; soundness reduced to the cited correlated-agreement theorem |

Conventions:
- Field `F` arbitrary (any characteristic). Values "independent of $x$" are vectors in an `F`-module `V`.
- Results imported from the literature (e.g. Gao–Kan–Li, Thm 3) enter as explicitly named hypotheses, never as hidden axioms.

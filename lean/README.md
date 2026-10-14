# SPARK — Lean 4 formalization

Section-by-section formalization of `../paper/spark.tex`, using the pinned Lean 4.23.0 and Mathlib revision in `lake-manifest.json`.

Build from this directory:
```
lake build
```

| Paper section | Lean file | Coverage |
|---|---|---|
| 2 Gates | `SparkLean/Gates.lean` | Parametrization, decomposition, uniqueness, collapse, interpolation/gate rules, and sum rule. Probabilistic uniformity is not formalized. |
| 3 Gate code | `SparkLean/Code.lean` | Recursive encoding, closed form, prefix coordinates and sibling property, zero/addition/scalar preservation, cost recurrence, and exact support of the per-layer obstruction. |
| 3 Per-layer weight | `SparkLean/CodeWeight.lean` | All-ones/root equivalence and cardinality; exact obstruction weight, nonzero encoded witness, block length, and relative weight. |
| 3 Linear encoder | `SparkLean/CodeLinear.lean` | Compatible additive-group/module structures on recursive `ML`; bundled `encLinear`; dimension `2^i`; injectivity from distinct node points; surjectivity for one root by equal finite dimensions. |
| 3 Code distance | `SparkLean/CodeDistance.lean` | Generic finite-coordinate weight and Hamming distance; minimum and relative minimum distance of a linear code; minimum attainment; equivalence with distances between distinct words; encoder image `gateCode`; per-layer upper bound `Δ(C_i) ≤ 1 / 2^i`. |
| 3 Extension of scalars | `SparkLean/CodeScalarExtension.lean` | Extended code as the `K`-span of the embedded base-field code; weight-preserving embedding; nonzero base-field projection with no larger support; both minimum-distance inequalities; equality of absolute and relative minimum distances, including for `gateCode`. Arbitrary field extensions are supported. |
| 3 Rate one | `SparkLean/CodeRateOne.lean` | Full word space has minimum distance one; with one root and distinct node points, every word is a codeword and relative minimum distance equals `1 / 2^i`. |
| 3 Later distance/setup results | Not yet implemented | Per-node random-family bounds, rank-saturation/augmentation, generic MDS, checked setup, and zero-structure results. |
| 4 Deterministic folding | `SparkLean/Fold.lean` | Sibling interpolation fold, gate-weight formula, encoding compatibility (including base-field words and extension-field challenges), iterated evaluation, affine line form, interpolation bijection and uniqueness, exact block agreement, and contraction in the paper's block metric. |
| 4 Proximity | Deferred | Line proximity and the challenge-count/probability corollary are not formalized. Dependencies and a counterexample to the corollary at `δ = 0` are recorded in [folding-proximity.md](docs/folding-proximity.md). |
| 5–6 Protocol | Not yet implemented | No protocol, completeness, or soundness files are present. |

Key theorem names:
- Distance: `minimumDistance_attained`, `distance_values`, `perLayer_minimumDistance_le`.
- Scalar extension: `exists_baseWord_le_weight`, `extendedCode_minimumDistance_le`, `minimumDistance_le_extendedCode`, `extendedCode_minimumDistance`, `extendedCode_relativeMinimumDistance`, `gateCode_scalarExtension_distance`.
- Rate one: `ML.finrank`, `enc_injective`, `enc_surjective_of_injective`, `enc_surjective`, `gateCode_eq_top`, `minimumDistance_top`, `rateOne_of_injective`, `rateOne`.
- Folding: `fold_enc`, `fold_enc_map`, `foldAll_enc`, `fold_gate_weights`, `fold_line`, `foldLineEquiv`, `fold_coefficients_unique`, `fold_block_agreement_iff`, `fold_line_codeword`, `fold_hammingDistance_le_blocks`, `fold_contraction`.

Definitions and hypotheses:
- `wordWeight` and `hammingDistance` reuse Mathlib's finite-coordinate Hamming functions. `wordWeight_eq_hammingWeight` identifies the generic weight with the established `hammingWeight` on `Pos`. `minimumDistance` is the least weight of a nonzero codeword; `distance_values` proves the equivalence with the pairwise definition for linear codes. The zero code has minimum distance zero by explicit convention. Relative distance is rational-valued, and zero block length also gives zero.
- `β` is an arbitrary root type; the paper specializes it to `Fin k → Bool`, of cardinality `2^k`. At layer `i`, block length is `|β| * 2^i`. The per-layer obstruction has weight `|β|` and, for nonempty finite `β`, relative weight `1 / 2^i`. Its theorem proves only the minimum-distance upper bound, not equality for general per-layer codes.
- `extendedCode C` is `Submodule.span K (extendWord '' C)`, the usual scalar-extended code inside `K^ι`. Applying any `F`-linear functional `K → F` coordinatewise returns a word in `C`. Algebraic-dual separation (from vector-space freeness) supplies a nonzero projection. This argument requires neither a finite field nor a finite-degree extension. Both inequalities also handle the zero code.
- Rate one uses a unique root (`k = 0`). `rateOne_of_injective` states the exact encoder assumption. `rateOne` proves injectivity from `T i ω false ≠ T i ω true` at every node; actual gates supply this via `Gate.t0_ne_t1`. Positive minimum distance of an image code alone does **not** imply injectivity of an arbitrary encoder. The proof does not make that inference, and gate separation removes the need for the paper's additional positivity hypothesis.
- The recursive layer index runs opposite to the paper's variable index (`j = n - i` for `T i`). For per-node families, `pt_siblings` proves the sibling claim at each recursive layer. The paper's broader sentence about changing any one path bit needs qualification: an inner bit can also affect outer gate points.
- The encoding cost theorem solves the paper's stated recurrence; it is not an operational cost semantics. The scalar-extension code is defined concretely as a span; no separate tensor-product equivalence is constructed.
- A fold from `i + 1` to `i` corresponds to the paper's `j = n - i`. `fold_enc` requires distinct sibling points only at that layer and proves `fold_z(enc(u, v)) = enc(u + z v)`. `fold_enc_map` also handles a field inclusion `F → K` and arbitrary `z ∈ K`, with `ML.map` and `enc_map` making coefficient and word inclusion explicit. `foldAll_enc` assumes separation throughout the supplied gate-point family and consumes challenges in outer-variable order.
- `foldA` and `foldB` are the paper's unique interpolation coefficients. `fold_line` proves `fold_z(w) = A(w) + z B(w)`. `foldLineEquiv` gives the bijection with coefficient-word pairs; `fold_line_codeword` supplies the upper codeword and exact block-agreement equivalence for two lower codewords. The gate-weight formula reuses `Gate.gate_rule_weights`; compatibility reuses `Gate.affine_interp`.
- `positionDistance` divides the number of unequal symbols by the layer length. `blockDistance` divides the number of unequal **sibling pairs** by the number of parents. `fold_contraction` proves `dpos(fold_z(w), fold_z(w')) ≤ dblk(w, w')`. This locality bound needs only finite `β`, not point separation or a finite field; an empty root type gives distance zero by the existing rational convention. Interpolation correctness and uniqueness do require point separation.
- The deterministic §4 claims are consistent with their definitions. The deferred folding-preserves-distance corollary is false at its allowed endpoint `δ = 0`: its proof cancels `δ`. A concrete `F₅` counterexample and possible repairs are documented separately; neither the paper nor a formal theorem has been silently changed.

Validation (2026-10-14): `lake build SparkLean.Fold` and the full `lake build`
(7224 jobs) pass. The §3 targeted builds also passed. All modules are imported by the root library.
A `#print axioms` audit of all 31 declarations in `Fold.lean` reports only `propext`,
`Classical.choice`, and `Quot.sound`, with no `sorryAx`; the earlier audit of the 43 §3
declarations found the same standard foundations. A source scan finds no `sorry`, `admit`,
or axiom declarations in the project. Pinned versions are unchanged. Existing linter warnings
in `Gates.lean` and `Code.lean` predate these results; `Fold.lean` builds without warnings.

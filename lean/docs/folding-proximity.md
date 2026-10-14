# Deferred §4 line proximity

This file records the dependencies of `lem:lineprox` and `cor:foldprox` in
`../paper/spark.tex`. Neither result is declared as an axiom or assumed theorem
in Lean. The line-proximity lemma is a counting statement; a probability bound
additionally needs a uniform distribution on a finite challenge field.

The paper's line-proximity statement is: for a linear code `C ⊆ K^N` with
minimum relative distance at least `Δ`, `0 ≤ δ < Δ / 3`, and words `A, B`, let
`Z = {z : dpos(A + z B, C) ≤ δ}`. If `|Z| = M ≥ 2`, there are `a, b ∈ C` such
that the number of positions with `(A(p), B(p)) ≠ (a(p), b(p))` is at most
`M / (M - 1) * δ * N`.

Dependencies still to formalize:

- Distance from a word to a nonempty code, including attainment, for both
  position and block metrics. Existing `minimumDistance` concerns distances
  *between codewords*, not distance from an arbitrary word to a code.
- Finite challenge counting (`Fintype K`, or an explicitly finite challenge
  set). The notation section only describes `K/F` as an extension; finiteness
  is needed for the finite counts and for uniform challenge probabilities.
- The minimum-distance agreement lemma: two codewords agreeing on more than
  `(1 - Δ) N` positions coincide. The triple-intersection bound gives more
  than this many positions because `3 δ < Δ`.
- Construction of `a, b ∈ C` from two distinct challenges and their nearby
  codewords, using linearity and division by the nonzero challenge difference.
- A nonzero affine function vanishes at at most one challenge, plus double
  counting of the agreement incidences on the set of unequal coefficient pairs.
- The identification of the paper's scalar-extended upper code with sibling
  evaluations of pairs from the scalar-extended lower code. `joinWord_mem_gateCode`
  and `fold_line_codeword` establish this codeword construction and exact block
  agreement for the encoder over the challenge field; `fold_enc_map` handles
  compatibility of included base-field codewords with extension-field challenges.
  A separate identification
  with the base-field code's `extendedCode` remains to be supplied when using
  the tensor/span notation across both fields.

Already available: the exact sibling-pair metric, `fold_contraction`, the
interpolation bijection `foldLineEquiv`, `fold_block_agreement_iff`, encoder
linearity, and `extendedCode_relativeMinimumDistance`.

## Discrepancy in the folding-preserves-distance corollary

The paper allows `δ = 0` in `cor:foldprox`, assumes
`dblk(w, C_upper ⊗ K) ≥ (1 + η) δ`, and concludes that the number of close
challenges is at most `1 + 1 / η`. Its proof cancels `δ`, which is invalid
when `δ = 0`. The statement as written is false at that endpoint.

Concrete counterexample: take `F = K = F₅`, one root (`k = 0`), one layer,
structural points `0, 1`, and `w = 0`. These points come from a valid gate
with `a = 0`, `b = -1`, `c = d = 1`, and determinant `1`. The lower code is
the full length-one code and has relative minimum distance `1`. Set `δ = 0`
and `η = 1`. The premise is `0 ≥ 0`, and all five challenges fold `w` to
zero, a lower codeword. The claimed conclusion is `5 ≤ 2`.

Requiring `δ > 0` repairs this cancellation. Alternatively, a strict
block-distance premise handles the zero-radius endpoint separately. No such
repair has been silently inserted into a Lean theorem or the paper. The
line-proximity lemma itself and the deterministic compatibility, line form,
and contraction statements are not affected by this endpoint discrepancy.

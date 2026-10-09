// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{encode::GateFamily, field::F128, gates::Gate};
use rayon::prelude::*;

/// Fold one layer. `word` must be laid out in adjacent sibling pairs.
pub fn fold_level(word: &[F128], gates: &[Gate], z: F128) -> Vec<F128> {
    assert_eq!(word.len(), 2 * gates.len());
    word.par_chunks_exact(2)
        .zip(gates.par_iter().copied())
        .map(|(w, gate)| gate.fold_pair(w[0], w[1], z))
        .collect()
}

/// Same operation when lambdas are already precomputed.
pub fn fold_level_precomputed(word: &[F128], lambdas: &[F128]) -> Vec<F128> {
    assert_eq!(word.len(), 2 * lambdas.len());
    word.par_chunks_exact(2)
        .zip(lambdas.par_iter().copied())
        .map(|(w, lambda)| Gate::fold_pair_with_lambda(w[0], w[1], lambda))
        .collect()
}

/// Fold a top-level encoded word through all n variables.
/// z[0] is the challenge for x1, z[n-1] for xn.
pub fn fold_all(mut word: Vec<F128>, family: &GateFamily, z: &[F128]) -> Vec<F128> {
    assert_eq!(z.len(), family.n);
    for (round, level) in family.levels.iter().rev().enumerate() {
        word = fold_level(&word, &level.gates, z[round]);
    }
    word
}

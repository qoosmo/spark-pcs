#![allow(clippy::needless_range_loop)]
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::{Duration, Instant};

use crate::{
    encode::{encode, GateFamily},
    field::F128,
    fold::fold_level,
    merkle::{Hash, MerkleMultiOpening, MerkleTree},
};

#[derive(Clone, Debug)]
pub struct SparkProof {
    /// Roots after fold rounds 1..n-1. The initial root is the commitment.
    pub folded_roots: Vec<Hash>,
    /// Claimed multilinear evaluation at the Fiat-Shamir point.
    pub eval: F128,
    /// One shared Merkle multiproof per committed layer.
    /// Query indices are Fiat-Shamir derived, sorted and deduplicated by the verifier.
    pub layer_openings: Vec<MerkleMultiOpening>,
}

impl SparkProof {
    /// Exact byte count of v0.4 proof material, excluding the initial commitment root.
    /// Query indices and fold challenges are Fiat-Shamir derived and not serialized.
    pub fn serialized_size_bytes(&self) -> usize {
        self.folded_roots.len() * 32
            + 16
            + self
                .layer_openings
                .iter()
                .map(MerkleMultiOpening::serialized_size_bytes)
                .sum::<usize>()
    }
}

#[derive(Debug)]
pub struct CompleteTimings {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub verify: Duration,
    pub commitment: Hash,
    pub proof: SparkProof,
    pub verified: bool,
}

impl CompleteTimings {
    #[inline]
    pub fn commit_total(&self) -> Duration {
        self.encode + self.commit0
    }

    #[inline]
    pub fn open_total(&self) -> Duration {
        self.fold_total + self.commit_folds + self.query_open
    }

    #[inline]
    pub fn prover_total(&self) -> Duration {
        self.commit_total() + self.open_total()
    }
}

fn absorb_root(state: &mut Vec<u8>, root: &Hash) {
    state.extend_from_slice(root);
}

fn challenge_field(state: &[u8], label: &[u8], counter: u64) -> F128 {
    let mut h = blake3::Hasher::new();
    h.update(b"SPARK-BINARY-FS-v0.4");
    h.update(label);
    h.update(&counter.to_le_bytes());
    h.update(state);
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest.as_bytes()[..16]);
    F128(u128::from_le_bytes(b))
}

fn challenge_index(state: &[u8], counter: u64, modulus: usize) -> usize {
    assert!(modulus > 0);
    let mut h = blake3::Hasher::new();
    h.update(b"SPARK-BINARY-QUERY-v0.4");
    h.update(&counter.to_le_bytes());
    h.update(state);
    let digest = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest.as_bytes()[..8]);
    (u64::from_le_bytes(b) as usize) % modulus
}

fn derive_fold_challenges(commitment: &Hash, folded_roots: &[Hash], n: usize) -> Vec<F128> {
    let mut state = Vec::with_capacity(32 * n);
    absorb_root(&mut state, commitment);
    let mut zs = Vec::with_capacity(n);
    for r in 0..n {
        let z = challenge_field(&state, b"fold", r as u64);
        zs.push(z);
        if r + 1 < n {
            absorb_root(&mut state, &folded_roots[r]);
        }
    }
    zs
}

fn query_state(commitment: &Hash, folded_roots: &[Hash], eval: F128) -> Vec<u8> {
    let mut state = Vec::with_capacity(32 * (folded_roots.len() + 1) + 16);
    absorb_root(&mut state, commitment);
    for root in folded_roots {
        absorb_root(&mut state, root);
    }
    state.extend_from_slice(&eval.to_le_bytes());
    state
}

fn derive_queries(
    commitment: &Hash,
    folded_roots: &[Hash],
    eval: F128,
    num_queries: usize,
    initial_leaves: usize,
) -> Vec<usize> {
    let state = query_state(commitment, folded_roots, eval);
    (0..num_queries)
        .map(|i| challenge_index(&state, i as u64, initial_leaves))
        .collect()
}

fn unique_layer_indices(q0s: &[usize], round: usize) -> Vec<usize> {
    let mut out = q0s.iter().map(|q| q >> round).collect::<Vec<_>>();
    out.sort_unstable();
    out.dedup();
    out
}

#[inline]
fn value_for_index(
    indices: &[usize],
    opening: &MerkleMultiOpening,
    pair_index: usize,
) -> Option<[F128; 2]> {
    indices
        .binary_search(&pair_index)
        .ok()
        .map(|p| opening.values[p])
}

pub fn verify_proof(
    family: &GateFamily,
    commitment: &Hash,
    proof: &SparkProof,
    num_queries: usize,
) -> bool {
    if family.n == 0
        || proof.folded_roots.len() + 1 != family.n
        || proof.layer_openings.len() != family.n
        || num_queries == 0
    {
        return false;
    }

    let zs = derive_fold_challenges(commitment, &proof.folded_roots, family.n);
    let initial_leaves = 1usize << (family.n + family.k - 1);
    let q0s = derive_queries(
        commitment,
        &proof.folded_roots,
        proof.eval,
        num_queries,
        initial_leaves,
    );

    let mut layer_indices = Vec::with_capacity(family.n);
    for r in 0..family.n {
        let indices = unique_layer_indices(&q0s, r);
        let leaf_count = initial_leaves >> r;
        let root = if r == 0 {
            commitment
        } else {
            &proof.folded_roots[r - 1]
        };
        if !MerkleTree::verify_pairs(root, leaf_count, &indices, &proof.layer_openings[r]) {
            return false;
        }
        layer_indices.push(indices);
    }

    // Check the local SPARK fold relation for every Fiat-Shamir query chain.
    for &q0 in &q0s {
        for r in 0..family.n {
            let pair_index = q0 >> r;
            let opening = &proof.layer_openings[r];
            let values = match value_for_index(&layer_indices[r], opening, pair_index) {
                Some(v) => v,
                None => return false,
            };

            let level = &family.levels[family.n - 1 - r];
            if pair_index >= level.gates.len() {
                return false;
            }
            let folded = level.gates[pair_index].fold_pair(values[0], values[1], zs[r]);

            if r + 1 < family.n {
                let next_pair = q0 >> (r + 1);
                let next_values = match value_for_index(
                    &layer_indices[r + 1],
                    &proof.layer_openings[r + 1],
                    next_pair,
                ) {
                    Some(v) => v,
                    None => return false,
                };
                let expected = next_values[pair_index & 1];
                if folded != expected {
                    return false;
                }
            } else if folded != proof.eval {
                return false;
            }
        }
    }

    true
}

/// Complete SPARK PCS prototype v0.4:
/// - flat ping-pong encoder,
/// - parallel Merkle construction,
/// - zero-copy retention of committed words,
/// - one Merkle multiproof per layer,
/// - full Fiat-Shamir verifier.
pub fn prove_and_verify(
    coeffs: &[F128],
    family: &GateFamily,
    num_queries: usize,
) -> CompleteTimings {
    assert!(family.n > 0);
    assert!(num_queries > 0);

    let t = Instant::now();
    let mut word = encode(coeffs, family);
    let encode_t = t.elapsed();

    let t = Instant::now();
    let tree0 = MerkleTree::from_pairs(&word);
    let commitment = tree0.root();
    let commit0_t = t.elapsed();

    // Retain committed layers without cloning their words. v0.3 cloned every layer.
    let mut words = Vec::with_capacity(family.n);
    let mut trees = Vec::with_capacity(family.n);
    trees.push(tree0);

    let mut folded_roots = Vec::with_capacity(family.n.saturating_sub(1));
    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;

    let mut transcript_state = Vec::with_capacity(32 * family.n);
    absorb_root(&mut transcript_state, &commitment);

    for (r, level) in family.levels.iter().rev().enumerate() {
        let z = challenge_field(&transcript_state, b"fold", r as u64);

        let t = Instant::now();
        let next_word = fold_level(&word, &level.gates, z);
        fold_total += t.elapsed();

        // The current word is committed and needed later for multiproof values.
        words.push(word);
        word = next_word;

        if r + 1 < family.n {
            let t = Instant::now();
            let tree = MerkleTree::from_pairs(&word);
            let root = tree.root();
            commit_folds += t.elapsed();
            folded_roots.push(root);
            absorb_root(&mut transcript_state, &root);
            trees.push(tree);
        }
    }

    debug_assert_eq!(words.len(), family.n);
    debug_assert_eq!(trees.len(), family.n);
    debug_assert_eq!(word.len(), 1usize << family.k);
    let eval = word[0];
    debug_assert!(word.iter().all(|&x| x == eval));

    let t = Instant::now();
    let initial_leaves = 1usize << (family.n + family.k - 1);
    let q0s = derive_queries(
        &commitment,
        &folded_roots,
        eval,
        num_queries,
        initial_leaves,
    );

    let mut layer_openings = Vec::with_capacity(family.n);
    for r in 0..family.n {
        let indices = unique_layer_indices(&q0s, r);
        layer_openings.push(trees[r].open_pairs(&words[r], &indices));
    }
    let query_open = t.elapsed();

    let proof = SparkProof {
        folded_roots,
        eval,
        layer_openings,
    };

    let t = Instant::now();
    let verified = verify_proof(family, &commitment, &proof, num_queries);
    let verify = t.elapsed();

    CompleteTimings {
        encode: encode_t,
        commit0: commit0_t,
        fold_total,
        commit_folds,
        query_open,
        verify,
        commitment,
        proof,
        verified,
    }
}

// Legacy timing API retained for old benches.
#[derive(Debug)]
pub struct Timings {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub final_word: Vec<F128>,
    pub roots: Vec<Hash>,
}

pub fn commit_and_fold<R: rand::RngCore>(
    coeffs: &[F128],
    family: &GateFamily,
    rng: &mut R,
) -> Timings {
    let t = Instant::now();
    let mut word = encode(coeffs, family);
    let encode_t = t.elapsed();

    let t = Instant::now();
    let mut roots = vec![MerkleTree::from_pairs(&word).root()];
    let commit0_t = t.elapsed();

    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;

    for (round, level) in family.levels.iter().rev().enumerate() {
        let z = F128::random(rng);
        let t = Instant::now();
        word = fold_level(&word, &level.gates, z);
        fold_total += t.elapsed();

        if round + 1 < family.n {
            let t = Instant::now();
            roots.push(MerkleTree::from_pairs(&word).root());
            commit_folds += t.elapsed();
        }
    }

    Timings {
        encode: encode_t,
        commit0: commit0_t,
        fold_total,
        commit_folds,
        final_word: word,
        roots,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn complete_proof_verifies() {
        let mut rng = StdRng::seed_from_u64(7);
        let n = 6;
        let k = 2;
        let family = GateFamily::random(n, k, &mut rng);
        let coeffs = (0..(1usize << n))
            .map(|_| F128::random(&mut rng))
            .collect::<Vec<_>>();
        let out = prove_and_verify(&coeffs, &family, 8);
        assert!(out.verified);
        assert!(out.proof.serialized_size_bytes() > 0);
    }

    #[test]
    fn tampered_query_fails() {
        let mut rng = StdRng::seed_from_u64(8);
        let n = 5;
        let k = 2;
        let family = GateFamily::random(n, k, &mut rng);
        let coeffs = (0..(1usize << n))
            .map(|_| F128::random(&mut rng))
            .collect::<Vec<_>>();
        let mut out = prove_and_verify(&coeffs, &family, 4);
        assert!(out.verified);
        out.proof.layer_openings[0].values[0][0] += F128::ONE;
        assert!(!verify_proof(&family, &out.commitment, &out.proof, 4));
    }
}

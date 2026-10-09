#![allow(clippy::needless_range_loop, clippy::too_many_arguments)]
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    encode::{derive_gate_level_key, derive_raw_gate_from_level_key, encode, GateFamily},
    extfield::F256,
    field::{batch_inverse, F128},
    gates::Gate,
    merkle_v05::{CompactOpening, Hash, HashKind, MerkleTreeV05, MultiOpening},
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct SparseProofV06 {
    pub folded_roots: Vec<Hash>,
    pub eval: F256,
    pub grind_nonce: Option<u64>,
    pub opening0: MultiOpening<F128>,
    pub folded_openings: Vec<CompactOpening<F256>>,
}

impl SparseProofV06 {
    pub fn serialized_size_bytes(&self) -> usize {
        self.folded_roots.len() * 32
            + 32
            + self.grind_nonce.map(|_| 8).unwrap_or(0)
            + self.opening0.serialized_size_bytes()
            + self
                .folded_openings
                .iter()
                .map(|x| x.serialized_size_bytes())
                .sum::<usize>()
    }
}

#[derive(Debug)]
pub struct SparseTimingsV06 {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub grind: Duration,
    pub gate_derive_verify: Duration,
    pub gate_prf_verify: Duration,
    pub gate_batch_inverse_verify: Duration,
    pub gate_build_verify: Duration,
    pub verify_checks: Duration,
    pub verify_transcript: Duration,
    pub verify_merkle: Duration,
    pub verify_folding: Duration,
    pub verify_other: Duration,
    pub commitment: Hash,
    pub proof: SparseProofV06,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyProfileV07 {
    pub transcript: Duration,
    pub gate_derivation: Duration,
    pub gate_prf: Duration,
    pub gate_batch_inverse: Duration,
    pub gate_build: Duration,
    pub merkle: Duration,
    pub folding: Duration,
    pub other: Duration,
}
impl VerifyProfileV07 {
    pub fn total(&self) -> Duration {
        self.transcript + self.gate_derivation + self.merkle + self.folding + self.other
    }
    pub fn checks(&self) -> Duration {
        self.transcript + self.merkle + self.folding + self.other
    }
}
impl SparseTimingsV06 {
    pub fn commit_total(&self) -> Duration {
        self.encode + self.commit0
    }
    pub fn open_total(&self) -> Duration {
        self.fold_total + self.commit_folds + self.query_open
    }
    pub fn prover_total(&self) -> Duration {
        self.commit_total() + self.open_total() + self.grind
    }
    pub fn verify_total(&self) -> Duration {
        self.gate_derive_verify + self.verify_checks
    }
}

fn hash_parts(kind: HashKind, parts: &[&[u8]]) -> [u8; 32] {
    match kind {
        HashKind::Blake3 => {
            let mut h = blake3::Hasher::new();
            for p in parts {
                h.update(p);
            }
            *h.finalize().as_bytes()
        }
        HashKind::Sha256 => {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().into()
        }
    }
}
fn challenge_field(state: &[u8], label: &[u8], counter: u64, kind: HashKind) -> F256 {
    F256::from_le_bytes(hash_parts(
        kind,
        &[
            b"SPARK-FS-SPARSE-v0.6",
            label,
            &counter.to_le_bytes(),
            state,
        ],
    ))
}
fn challenge_index(state: &[u8], counter: u64, modulus: usize, kind: HashKind) -> usize {
    let d = hash_parts(
        kind,
        &[b"SPARK-QUERY-SPARSE-v0.6", &counter.to_le_bytes(), state],
    );
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    (u64::from_le_bytes(b) as usize) % modulus
}
fn init_state(commitment: &Hash, commit_every: usize) -> Vec<u8> {
    let mut st = Vec::new();
    st.extend_from_slice(commitment);
    st.extend_from_slice(b"SPARK-SCHEDULE-v0.6");
    st.extend_from_slice(&(commit_every as u64).to_le_bytes());
    st
}
fn committed_boundaries(n: usize, commit_every: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut b = commit_every;
    while b < n {
        out.push(b);
        b += commit_every;
    }
    out
}
fn derive_zs_sparse(
    commitment: &Hash,
    roots: &[Hash],
    n: usize,
    commit_every: usize,
    kind: HashKind,
) -> Option<Vec<F256>> {
    let boundaries = committed_boundaries(n, commit_every);
    if roots.len() != boundaries.len() {
        return None;
    }
    let mut st = init_state(commitment, commit_every);
    let mut z = Vec::with_capacity(n);
    let mut ri = 0usize;
    for r in 0..n {
        let zr = challenge_field(&st, b"fold", r as u64, kind);
        z.push(zr);
        let b = r + 1;
        if b < n {
            if b % commit_every == 0 {
                st.extend_from_slice(&roots[ri]);
                ri += 1;
            } else {
                st.extend_from_slice(b"SPARK-SKIP-v0.6");
                st.extend_from_slice(&zr.to_le_bytes());
            }
        }
    }
    Some(z)
}
fn query_transcript(commitment: &Hash, roots: &[Hash], eval: F256, commit_every: usize) -> Vec<u8> {
    let mut st = init_state(commitment, commit_every);
    for r in roots {
        st.extend_from_slice(r);
    }
    st.extend_from_slice(&eval.to_le_bytes());
    st
}
fn leading_zero_bits(d: &Hash) -> u32 {
    let mut z = 0u32;
    for &b in d {
        if b == 0 {
            z += 8;
        } else {
            z += b.leading_zeros();
            break;
        }
    }
    z
}
fn grind_seed(
    commitment: &Hash,
    roots: &[Hash],
    eval: F256,
    commit_every: usize,
    kind: HashKind,
) -> Hash {
    let st = query_transcript(commitment, roots, eval, commit_every);
    hash_parts(kind, &[b"SPARK-GRIND-SEED-SPARSE-v0.6", &st])
}
fn valid_grind_nonce(seed: &Hash, nonce: u64, bits: u32, kind: HashKind) -> bool {
    if bits == 0 {
        return nonce == 0;
    }
    let d = hash_parts(
        kind,
        &[b"SPARK-GRIND-SPARSE-v0.6", seed, &nonce.to_le_bytes()],
    );
    leading_zero_bits(&d) >= bits
}
fn find_grind_nonce(seed: &Hash, bits: u32, kind: HashKind) -> u64 {
    assert!(bits <= 32);
    if bits == 0 {
        return 0;
    }
    const CHUNK: u64 = 1 << 16;
    let mut start = 0u64;
    loop {
        let end = start.checked_add(CHUNK).expect("grinding nonce overflow");
        if let Some(nonce) = (start..end)
            .into_par_iter()
            .filter(|&nonce| valid_grind_nonce(seed, nonce, bits, kind))
            .min()
        {
            return nonce;
        }
        start = end;
    }
}
fn derive_queries(
    commitment: &Hash,
    roots: &[Hash],
    eval: F256,
    nonce: Option<u64>,
    s: usize,
    leaves: usize,
    commit_every: usize,
    kind: HashKind,
) -> Vec<usize> {
    let mut st = query_transcript(commitment, roots, eval, commit_every);
    if let Some(n) = nonce {
        st.extend_from_slice(b"SPARK-GRIND-NONCE-SPARSE-v0.6");
        st.extend_from_slice(&n.to_le_bytes());
    }
    (0..s)
        .map(|i| challenge_index(&st, i as u64, leaves, kind))
        .collect()
}

#[inline]
fn fold_first(g: Gate, w0: F128, w1: F128, z: F256) -> F256 {
    let lambda = (z + F256::from_base(g.t0)).mul_base(g.inv_dt);
    F256::from_base(w0) + lambda.mul_base(w1 + w0)
}
#[inline]
fn fold_ext(g: Gate, w0: F256, w1: F256, z: F256) -> F256 {
    let lambda = (z + F256::from_base(g.t0)).mul_base(g.inv_dt);
    w0 + lambda * (w1 + w0)
}
fn fold_first_level(word: &[F128], gates: &[Gate], z: F256) -> Vec<F256> {
    word.par_chunks_exact(2)
        .zip(gates.par_iter().copied())
        .map(|(w, g)| fold_first(g, w[0], w[1], z))
        .collect()
}
fn fold_ext_level(word: &[F256], gates: &[Gate], z: F256) -> Vec<F256> {
    word.par_chunks_exact(2)
        .zip(gates.par_iter().copied())
        .map(|(w, g)| fold_ext(g, w[0], w[1], z))
        .collect()
}

/// Pair leaves of E_a needed to follow all sampled chains across d skipped/committed folds.
fn source_pair_indices(q0s: &[usize], a: usize, d: usize) -> Vec<usize> {
    debug_assert!(d >= 1);
    let width = 1usize << (d - 1);
    let mut out = Vec::new();
    for &q in q0s {
        let p = q >> a;
        let base = (p / width) * width;
        out.extend(base..base + width);
    }
    out.sort_unstable();
    out.dedup();
    out
}
fn target_positions(q0s: &[usize], b: usize) -> Vec<usize> {
    debug_assert!(b >= 1);
    let mut out = q0s.iter().map(|q| q >> (b - 1)).collect::<Vec<_>>();
    out.sort_unstable();
    out.dedup();
    out
}

fn collect_sparse_gate_keys(n: usize, q0s: &[usize], commit_every: usize) -> Vec<(usize, usize)> {
    let mut keys = Vec::new();
    let mut a = 0usize;
    while a < n {
        let d = commit_every.min(n - a);
        let width = 1usize << (d - 1);
        let mut bases = q0s
            .iter()
            .map(|q| {
                let p = q >> a;
                (p / width) * width
            })
            .collect::<Vec<_>>();
        bases.sort_unstable();
        bases.dedup();
        for base in bases {
            let start_word = 2 * base;
            let mut len = 1usize << d;
            for t in 0..d {
                let pair_start = start_word >> (t + 1);
                for j in 0..(len / 2) {
                    keys.push((n - 1 - (a + t), pair_start + j));
                }
                len >>= 1;
            }
        }
        a += d;
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}
fn derive_sparse_gates_profiled(
    seed: u64,
    setup_counter: u64,
    keys: &[(usize, usize)],
) -> (Vec<Gate>, Duration, Duration, Duration) {
    let t = Instant::now();
    let mut raw = Vec::with_capacity(keys.len());
    let mut current_level = None;
    let mut level_key = [0u8; 32];
    for &(level, node) in keys {
        if current_level != Some(level) {
            level_key = derive_gate_level_key(seed, setup_counter, level);
            current_level = Some(level);
        }
        raw.push(derive_raw_gate_from_level_key(&level_key, node));
    }
    let prf_t = t.elapsed();

    let den = raw.iter().map(|(a, b)| *a + *b).collect::<Vec<_>>();
    let t = Instant::now();
    let inv = batch_inverse(&den);
    let inv_t = t.elapsed();

    let t = Instant::now();
    let gates = raw
        .into_iter()
        .zip(inv)
        .map(|((t0, t1), iv)| Gate::new(t0, t1, iv))
        .collect();
    let build_t = t.elapsed();

    (gates, prf_t, inv_t, build_t)
}

fn pair_at<T: Copy>(indices: &[usize], pairs: &[[T; 2]], p: usize) -> Option<[T; 2]> {
    indices.binary_search(&p).ok().map(|i| pairs[i])
}
#[inline(always)]
#[allow(dead_code)]
fn gate_at(keys: &[(usize, usize)], gates: &[Gate], level: usize, node: usize) -> Option<Gate> {
    keys.binary_search(&(level, node)).ok().map(|i| gates[i])
}

fn derive_fold_lambdas(
    n: usize,
    keys: &[(usize, usize)],
    gates: &[Gate],
    zs: &[F256],
) -> Vec<F256> {
    keys.iter()
        .zip(gates.iter().copied())
        .map(|(&(level, _), g)| {
            let round = n - 1 - level;
            (zs[round] + F256::from_base(g.t0)).mul_base(g.inv_dt)
        })
        .collect()
}

#[inline(always)]
fn lambda_at(keys: &[(usize, usize)], lambdas: &[F256], level: usize, node: usize) -> Option<F256> {
    keys.binary_search(&(level, node)).ok().map(|i| lambdas[i])
}

#[inline]
fn fold_first_lambda(lambda: F256, w0: F128, w1: F128) -> F256 {
    F256::from_base(w0) + lambda.mul_base(w1 + w0)
}

#[inline]
fn fold_ext_lambda(lambda: F256, w0: F256, w1: F256) -> F256 {
    w0 + lambda * (w1 + w0)
}
fn fold_block_first(
    n: usize,
    d: usize,
    base: usize,
    indices: &[usize],
    pairs: &[[F128; 2]],
    gate_keys: &[(usize, usize)],
    lambdas: &[F256],
) -> Option<F256> {
    let width = 1usize << (d - 1);
    let mut first = Vec::with_capacity(width);
    for p in base..base + width {
        let v = pair_at(indices, pairs, p)?;
        let lambda = lambda_at(gate_keys, lambdas, n - 1, p)?;
        first.push(fold_first_lambda(lambda, v[0], v[1]));
    }
    let start_word = 2 * base;
    let mut cur = first;
    for t in 1..d {
        let pair_start = start_word >> (t + 1);
        cur = cur
            .chunks_exact(2)
            .enumerate()
            .map(|(j, w)| {
                let lambda = lambda_at(gate_keys, lambdas, n - 1 - t, pair_start + j)
                    .expect("lambda present");
                fold_ext_lambda(lambda, w[0], w[1])
            })
            .collect();
    }
    cur.first().copied()
}
fn fold_block_ext(
    n: usize,
    a: usize,
    d: usize,
    base: usize,
    indices: &[usize],
    pairs: &[[F256; 2]],
    gate_keys: &[(usize, usize)],
    lambdas: &[F256],
) -> Option<F256> {
    let width = 1usize << (d - 1);
    let mut cur = Vec::with_capacity(1usize << d);
    for p in base..base + width {
        let v = pair_at(indices, pairs, p)?;
        cur.push(v[0]);
        cur.push(v[1]);
    }
    let start_word = 2 * base;
    for t in 0..d {
        let pair_start = start_word >> (t + 1);
        cur = cur
            .chunks_exact(2)
            .enumerate()
            .map(|(j, w)| {
                let lambda = lambda_at(gate_keys, lambdas, n - 1 - (a + t), pair_start + j)
                    .expect("lambda present");
                fold_ext_lambda(lambda, w[0], w[1])
            })
            .collect();
    }
    cur.first().copied()
}
fn known_from_first(
    n: usize,
    d: usize,
    q0s: &[usize],
    indices: &[usize],
    pairs: &[[F128; 2]],
    gate_keys: &[(usize, usize)],
    lambdas: &[F256],
) -> Option<HashMap<usize, F256>> {
    let width = 1usize << (d - 1);
    let mut out = HashMap::new();
    for &q in q0s {
        let pos = q >> (d - 1);
        if out.contains_key(&pos) {
            continue;
        }
        let p = q;
        let base = (p / width) * width;
        out.insert(
            pos,
            fold_block_first(n, d, base, indices, pairs, gate_keys, lambdas)?,
        );
    }
    Some(out)
}
fn known_from_ext(
    n: usize,
    a: usize,
    d: usize,
    q0s: &[usize],
    indices: &[usize],
    pairs: &[[F256; 2]],
    gate_keys: &[(usize, usize)],
    lambdas: &[F256],
) -> Option<HashMap<usize, F256>> {
    let width = 1usize << (d - 1);
    let mut out = HashMap::new();
    for &q in q0s {
        let pos = q >> (a + d - 1);
        if out.contains_key(&pos) {
            continue;
        }
        let p = q >> a;
        let base = (p / width) * width;
        out.insert(
            pos,
            fold_block_ext(n, a, d, base, indices, pairs, gate_keys, lambdas)?,
        );
    }
    Some(out)
}

pub fn verify_sparse_v06(
    seed: u64,
    setup_counter: u64,
    n: usize,
    k: usize,
    commitment: &Hash,
    proof: &SparseProofV06,
    s: usize,
    grind_bits: u32,
    commit_every: usize,
    kind: HashKind,
) -> (bool, VerifyProfileV07) {
    let total_start = Instant::now();
    let mut profile = VerifyProfileV07::default();

    if n == 0 || s == 0 || commit_every == 0 || commit_every > n || grind_bits > 32 {
        return (false, profile);
    }

    let transcript_start = Instant::now();
    let boundaries = committed_boundaries(n, commit_every);
    if proof.folded_roots.len() != boundaries.len()
        || proof.folded_openings.len() != boundaries.len()
    {
        profile.transcript = transcript_start.elapsed();
        profile.other = total_start
            .elapsed()
            .checked_sub(profile.transcript)
            .unwrap_or(Duration::ZERO);
        return (false, profile);
    }
    let zs = match derive_zs_sparse(commitment, &proof.folded_roots, n, commit_every, kind) {
        Some(x) => x,
        None => {
            profile.transcript = transcript_start.elapsed();
            profile.other = total_start
                .elapsed()
                .checked_sub(profile.transcript)
                .unwrap_or(Duration::ZERO);
            return (false, profile);
        }
    };
    let leaves0 = 1usize << (n + k - 1);
    let gs = grind_seed(
        commitment,
        &proof.folded_roots,
        proof.eval,
        commit_every,
        kind,
    );
    let nonce = match (grind_bits, proof.grind_nonce) {
        (0, None) => None,
        (0, Some(_)) => {
            profile.transcript = transcript_start.elapsed();
            return (false, profile);
        }
        (_, Some(x)) if valid_grind_nonce(&gs, x, grind_bits, kind) => Some(x),
        _ => {
            profile.transcript = transcript_start.elapsed();
            return (false, profile);
        }
    };
    let q0s = derive_queries(
        commitment,
        &proof.folded_roots,
        proof.eval,
        nonce,
        s,
        leaves0,
        commit_every,
        kind,
    );
    let keys = collect_sparse_gate_keys(n, &q0s, commit_every);
    profile.transcript = transcript_start.elapsed();

    let gate_start = Instant::now();
    let (gates, gate_prf, gate_batch_inverse, gate_build) =
        derive_sparse_gates_profiled(seed, setup_counter, &keys);
    profile.gate_derivation = gate_start.elapsed();
    profile.gate_prf = gate_prf;
    profile.gate_batch_inverse = gate_batch_inverse;
    profile.gate_build = gate_build;

    let lambda_start = Instant::now();
    let fold_lambdas = derive_fold_lambdas(n, &keys, &gates, &zs);
    profile.folding += lambda_start.elapsed();

    let d0 = commit_every.min(n);
    let ix0 = source_pair_indices(&q0s, 0, d0);

    let merkle_start = Instant::now();
    let ok0 = MerkleTreeV05::<F128>::verify_pairs(commitment, leaves0, &ix0, &proof.opening0, kind);
    profile.merkle += merkle_start.elapsed();
    if !ok0 {
        let accounted =
            profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
        profile.other = total_start
            .elapsed()
            .checked_sub(accounted)
            .unwrap_or(Duration::ZERO);
        return (false, profile);
    }

    let fold_start = Instant::now();
    let mut known = match known_from_first(
        n,
        d0,
        &q0s,
        &ix0,
        &proof.opening0.values,
        &keys,
        &fold_lambdas,
    ) {
        Some(x) => x,
        None => {
            profile.folding += fold_start.elapsed();
            let accounted =
                profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
            profile.other = total_start
                .elapsed()
                .checked_sub(accounted)
                .unwrap_or(Duration::ZERO);
            return (false, profile);
        }
    };
    profile.folding += fold_start.elapsed();

    let mut a = d0;
    for (j, &b) in boundaries.iter().enumerate() {
        debug_assert_eq!(b, a);
        let d = commit_every.min(n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let leaves = leaves0 >> b;

        let merkle_start = Instant::now();
        let pairs_result = MerkleTreeV05::<F256>::verify_pairs_compact(
            &proof.folded_roots[j],
            leaves,
            &ix,
            &known,
            &proof.folded_openings[j],
            kind,
        );
        profile.merkle += merkle_start.elapsed();
        let pairs = match pairs_result {
            Some(v) => v,
            None => {
                let accounted =
                    profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
                profile.other = total_start
                    .elapsed()
                    .checked_sub(accounted)
                    .unwrap_or(Duration::ZERO);
                return (false, profile);
            }
        };

        let fold_start = Instant::now();
        known = match known_from_ext(n, b, d, &q0s, &ix, &pairs, &keys, &fold_lambdas) {
            Some(x) => x,
            None => {
                profile.folding += fold_start.elapsed();
                let accounted =
                    profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
                profile.other = total_start
                    .elapsed()
                    .checked_sub(accounted)
                    .unwrap_or(Duration::ZERO);
                return (false, profile);
            }
        };
        profile.folding += fold_start.elapsed();
        a = b + d;
    }

    let ok = a == n && !known.values().any(|&v| v != proof.eval);
    let accounted = profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
    profile.other = total_start
        .elapsed()
        .checked_sub(accounted)
        .unwrap_or(Duration::ZERO);
    (ok, profile)
}

pub fn prove_and_verify_sparse_v06(
    coeffs: &[F128],
    family: &GateFamily,
    seed: u64,
    setup_counter: u64,
    s: usize,
    grind_bits: u32,
    commit_every: usize,
    kind: HashKind,
) -> SparseTimingsV06 {
    assert!(commit_every >= 1 && commit_every <= family.n);
    let t = Instant::now();
    let word0 = encode(coeffs, family);
    let encode_t = t.elapsed();
    let t = Instant::now();
    let tree0 = MerkleTreeV05::<F128>::from_pairs(&word0, kind);
    let commitment = tree0.root();
    let commit0 = t.elapsed();

    let boundaries = committed_boundaries(family.n, commit_every);
    let mut committed_words = Vec::<Vec<F256>>::with_capacity(boundaries.len());
    let mut committed_trees = Vec::<MerkleTreeV05<F256>>::with_capacity(boundaries.len());
    let mut roots = Vec::with_capacity(boundaries.len());
    let mut state = init_state(&commitment, commit_every);
    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;
    let mut current_ext: Option<Vec<F256>> = None;
    let mut final_word = Vec::new();
    for (r, level) in family.levels.iter().rev().enumerate() {
        let z = challenge_field(&state, b"fold", r as u64, kind);
        let t = Instant::now();
        let next = if r == 0 {
            fold_first_level(&word0, &level.gates, z)
        } else {
            fold_ext_level(current_ext.as_ref().unwrap(), &level.gates, z)
        };
        fold_total += t.elapsed();
        let b = r + 1;
        if b < family.n && b % commit_every == 0 {
            let t = Instant::now();
            let tree = MerkleTreeV05::<F256>::from_pairs(&next, kind);
            let root = tree.root();
            commit_folds += t.elapsed();
            roots.push(root);
            state.extend_from_slice(&root);
            committed_words.push(next.clone());
            committed_trees.push(tree);
        } else if b < family.n {
            state.extend_from_slice(b"SPARK-SKIP-v0.6");
            state.extend_from_slice(&z.to_le_bytes());
        }
        if b == family.n {
            final_word = next.clone();
        }
        current_ext = Some(next);
    }
    let eval = final_word[0];
    debug_assert!(final_word.iter().all(|x| *x == eval));
    let gs = grind_seed(&commitment, &roots, eval, commit_every, kind);
    let t = Instant::now();
    let nonce = if grind_bits == 0 {
        None
    } else {
        Some(find_grind_nonce(&gs, grind_bits, kind))
    };
    let grind = t.elapsed();

    let t = Instant::now();
    let leaves0 = 1usize << (family.n + family.k - 1);
    let q0s = derive_queries(
        &commitment,
        &roots,
        eval,
        nonce,
        s,
        leaves0,
        commit_every,
        kind,
    );
    let d0 = commit_every.min(family.n);
    let ix0 = source_pair_indices(&q0s, 0, d0);
    let opening0 = tree0.open_pairs(&word0, &ix0);
    let mut fops = Vec::with_capacity(boundaries.len());
    for (j, &b) in boundaries.iter().enumerate() {
        let d = commit_every.min(family.n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let known_positions = target_positions(&q0s, b);
        fops.push(committed_trees[j].open_pairs_compact(
            &committed_words[j],
            &ix,
            &known_positions,
        ));
    }
    let query_open = t.elapsed();
    let proof = SparseProofV06 {
        folded_roots: roots,
        eval,
        grind_nonce: nonce,
        opening0,
        folded_openings: fops,
    };
    let (verified, verify_profile) = verify_sparse_v06(
        seed,
        setup_counter,
        family.n,
        family.k,
        &commitment,
        &proof,
        s,
        grind_bits,
        commit_every,
        kind,
    );
    SparseTimingsV06 {
        encode: encode_t,
        commit0,
        fold_total,
        commit_folds,
        query_open,
        grind,
        gate_derive_verify: verify_profile.gate_derivation,
        gate_prf_verify: verify_profile.gate_prf,
        gate_batch_inverse_verify: verify_profile.gate_batch_inverse,
        gate_build_verify: verify_profile.gate_build,
        verify_checks: verify_profile.checks(),
        verify_transcript: verify_profile.transcript,
        verify_merkle: verify_profile.merkle,
        verify_folding: verify_profile.folding,
        verify_other: verify_profile.other,
        commitment,
        proof,
        verified,
    }
}

#[cfg(test)]
mod sparse_auth_tests {
    use super::*;

    #[test]
    fn modified_final_en_is_rejected() {
        let seed = 12345u64;
        let n = 4usize;
        let k = 2usize;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let coeffs = (0..(1usize << n))
            .map(|i| F128((i as u128) + 1))
            .collect::<Vec<_>>();

        let run = prove_and_verify_sparse_v06(
            &coeffs,
            &checked.family,
            seed,
            checked.counter,
            4,
            0,
            2,
            HashKind::Blake3,
        );
        assert!(run.verified);

        let mut bad = run.proof.clone();
        bad.eval += F256::ONE;
        let (ok, _) = verify_sparse_v06(
            seed,
            checked.counter,
            n,
            k,
            &run.commitment,
            &bad,
            4,
            0,
            2,
            HashKind::Blake3,
        );
        assert!(!ok);
    }
}

// -----------------------------------------------------------------------------
// SPARK v0.9 transcript wrapper.
// This code intentionally reuses the v0.8 encoding, gates, Merkle layout,
// folding equations, and query-opening logic. Only Fiat--Shamir state
// construction and verifier-side parameter validation change.
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SparseProofV09 {
    pub proof_format_version: u8,
    pub header: Vec<u8>,
    pub body: SparseProofV06,
}

impl SparseProofV09 {
    pub fn serialized_size_bytes(&self) -> usize {
        1 + 4 + self.header.len() + self.body.serialized_size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyErrorV09 {
    VersionMismatch { expected: u8, got: u8 },
    InvalidParams(String),
    HeaderMismatch,
    InvalidProof,
}

#[derive(Debug)]
pub struct SparseTimingsV09 {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub grind: Duration,
    pub verify: VerifyProfileV07,
    pub commitment: Hash,
    pub proof: SparseProofV09,
    pub verified: bool,
    pub challenges: Vec<F256>,
}

impl SparseTimingsV09 {
    pub fn prover_total(&self) -> Duration {
        self.encode
            + self.commit0
            + self.fold_total
            + self.commit_folds
            + self.query_open
            + self.grind
    }

    pub fn verify_total(&self) -> Duration {
        self.verify.total()
    }
}

fn derive_zs_sparse_v09(
    params: &crate::transcript_v09::ParamsV09,
    commitment: &Hash,
    roots: &[Hash],
) -> Option<Vec<F256>> {
    let header = params.header().ok()?;
    let boundaries = committed_boundaries(params.n, params.commit_every);
    if roots.len() != boundaries.len() {
        return None;
    }

    let mut st = crate::transcript_v09::initial_state_v09(&header, commitment);
    let mut zs = Vec::with_capacity(params.n);
    let mut ri = 0usize;

    for r in 0..params.n {
        let z =
            crate::transcript_v09::challenge_field_v09(&st, b"fold", r as u64, params.hash_kind);
        zs.push(z);

        let b = r + 1;
        if b < params.n && b % params.commit_every == 0 {
            st.extend_from_slice(&roots[ri]);
            ri += 1;
        }
    }
    Some(zs)
}

fn final_state_sparse_v09(
    params: &crate::transcript_v09::ParamsV09,
    commitment: &Hash,
    roots: &[Hash],
    eval: F256,
) -> Option<Vec<u8>> {
    let header = params.header().ok()?;
    let boundaries = committed_boundaries(params.n, params.commit_every);
    if roots.len() != boundaries.len() {
        return None;
    }

    let mut st = crate::transcript_v09::initial_state_v09(&header, commitment);
    for root in roots {
        st.extend_from_slice(root);
    }
    crate::transcript_v09::append_single_last_v09(&mut st, eval);
    Some(st)
}

/// v0.9 verifier. Parameter validation happens before proof-body access.
pub fn verify_sparse_v09(
    params: &crate::transcript_v09::ParamsV09,
    commitment: &Hash,
    proof: &SparseProofV09,
) -> Result<VerifyProfileV07, VerifyErrorV09> {
    let total_start = Instant::now();
    let mut profile = VerifyProfileV07::default();

    params.validate().map_err(VerifyErrorV09::InvalidParams)?;

    if proof.proof_format_version != crate::transcript_v09::PROOF_FORMAT_VERSION_V09 {
        return Err(VerifyErrorV09::VersionMismatch {
            expected: crate::transcript_v09::PROOF_FORMAT_VERSION_V09,
            got: proof.proof_format_version,
        });
    }

    let expected_header = params
        .header()
        .map_err(VerifyErrorV09::InvalidParams)?
        .serialize();
    if proof.header != expected_header {
        return Err(VerifyErrorV09::HeaderMismatch);
    }

    let transcript_start = Instant::now();
    let boundaries = committed_boundaries(params.n, params.commit_every);
    if proof.body.folded_roots.len() != boundaries.len()
        || proof.body.folded_openings.len() != boundaries.len()
    {
        return Err(VerifyErrorV09::InvalidProof);
    }

    let zs = derive_zs_sparse_v09(params, commitment, &proof.body.folded_roots)
        .ok_or(VerifyErrorV09::InvalidProof)?;

    let leaves0 = 1usize << (params.n + params.k - 1);
    let final_state = final_state_sparse_v09(
        params,
        commitment,
        &proof.body.folded_roots,
        proof.body.eval,
    )
    .ok_or(VerifyErrorV09::InvalidProof)?;

    let gs = crate::transcript_v09::grind_seed_v09(&final_state, params.hash_kind);
    let nonce = match (params.g, proof.body.grind_nonce) {
        (0, None) => None,
        (0, Some(_)) => return Err(VerifyErrorV09::InvalidProof),
        (_, Some(x))
            if crate::transcript_v09::valid_grind_nonce_v09(&gs, x, params.g, params.hash_kind) =>
        {
            Some(x)
        }
        _ => return Err(VerifyErrorV09::InvalidProof),
    };

    let q0s = crate::transcript_v09::derive_queries_v09(
        &final_state,
        nonce,
        params.s,
        leaves0,
        params.hash_kind,
    );
    let keys = collect_sparse_gate_keys(params.n, &q0s, params.commit_every);
    profile.transcript = transcript_start.elapsed();

    let gate_start = Instant::now();
    let (gates, gate_prf, gate_batch_inverse, gate_build) =
        derive_sparse_gates_profiled(params.gate_seed, params.setup_counter, &keys);
    profile.gate_derivation = gate_start.elapsed();
    profile.gate_prf = gate_prf;
    profile.gate_batch_inverse = gate_batch_inverse;
    profile.gate_build = gate_build;

    let lambda_start = Instant::now();
    let fold_lambdas = derive_fold_lambdas(params.n, &keys, &gates, &zs);
    profile.folding += lambda_start.elapsed();

    let d0 = params.commit_every.min(params.n);
    let ix0 = source_pair_indices(&q0s, 0, d0);

    let merkle_start = Instant::now();
    let ok0 = MerkleTreeV05::<F128>::verify_pairs(
        commitment,
        leaves0,
        &ix0,
        &proof.body.opening0,
        params.hash_kind,
    );
    profile.merkle += merkle_start.elapsed();
    if !ok0 {
        return Err(VerifyErrorV09::InvalidProof);
    }

    let fold_start = Instant::now();
    let mut known = known_from_first(
        params.n,
        d0,
        &q0s,
        &ix0,
        &proof.body.opening0.values,
        &keys,
        &fold_lambdas,
    )
    .ok_or(VerifyErrorV09::InvalidProof)?;
    profile.folding += fold_start.elapsed();

    let mut a = d0;
    for (j, &b) in boundaries.iter().enumerate() {
        if b != a {
            return Err(VerifyErrorV09::InvalidProof);
        }

        let d = params.commit_every.min(params.n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let leaves = leaves0 >> b;

        let merkle_start = Instant::now();
        let pairs = MerkleTreeV05::<F256>::verify_pairs_compact(
            &proof.body.folded_roots[j],
            leaves,
            &ix,
            &known,
            &proof.body.folded_openings[j],
            params.hash_kind,
        )
        .ok_or(VerifyErrorV09::InvalidProof)?;
        profile.merkle += merkle_start.elapsed();

        let fold_start = Instant::now();
        known = known_from_ext(params.n, b, d, &q0s, &ix, &pairs, &keys, &fold_lambdas)
            .ok_or(VerifyErrorV09::InvalidProof)?;
        profile.folding += fold_start.elapsed();

        a = b + d;
    }

    if a != params.n || known.values().any(|&v| v != proof.body.eval) {
        return Err(VerifyErrorV09::InvalidProof);
    }

    let accounted = profile.transcript + profile.gate_derivation + profile.merkle + profile.folding;
    profile.other = total_start
        .elapsed()
        .checked_sub(accounted)
        .unwrap_or(Duration::ZERO);

    Ok(profile)
}

pub fn prove_and_verify_sparse_v09(
    coeffs: &[F128],
    family: &GateFamily,
    params: &crate::transcript_v09::ParamsV09,
) -> Result<SparseTimingsV09, VerifyErrorV09> {
    params.validate().map_err(VerifyErrorV09::InvalidParams)?;
    if params.t != 1 || family.n != params.n || family.k != params.k {
        return Err(VerifyErrorV09::InvalidParams(
            "single-proof params/family mismatch".into(),
        ));
    }

    let te = Instant::now();
    let word0 = encode(coeffs, family);
    let encode_t = te.elapsed();

    let tc = Instant::now();
    let tree0 = MerkleTreeV05::<F128>::from_pairs(&word0, params.hash_kind);
    let commitment = tree0.root();
    let commit0 = tc.elapsed();

    let header = params.header().map_err(VerifyErrorV09::InvalidParams)?;
    let boundaries = committed_boundaries(params.n, params.commit_every);
    let mut committed_words = Vec::<Vec<F256>>::with_capacity(boundaries.len());
    let mut committed_trees = Vec::<MerkleTreeV05<F256>>::with_capacity(boundaries.len());
    let mut roots = Vec::with_capacity(boundaries.len());
    let mut state = crate::transcript_v09::initial_state_v09(&header, &commitment);

    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;
    let mut current_ext: Option<Vec<F256>> = None;
    let mut final_word = Vec::new();

    for (r, level) in family.levels.iter().rev().enumerate() {
        let z =
            crate::transcript_v09::challenge_field_v09(&state, b"fold", r as u64, params.hash_kind);

        let tf = Instant::now();
        let next = if r == 0 {
            fold_first_level(&word0, &level.gates, z)
        } else {
            fold_ext_level(current_ext.as_ref().unwrap(), &level.gates, z)
        };
        fold_total += tf.elapsed();

        let b = r + 1;
        if b < family.n && b % params.commit_every == 0 {
            let tc = Instant::now();
            let tree = MerkleTreeV05::<F256>::from_pairs(&next, params.hash_kind);
            let root = tree.root();
            commit_folds += tc.elapsed();

            roots.push(root);
            state.extend_from_slice(&root);
            committed_words.push(next.clone());
            committed_trees.push(tree);
        }

        if b == family.n {
            final_word = next.clone();
        }
        current_ext = Some(next);
    }

    let eval = final_word[0];
    debug_assert!(final_word.iter().all(|x| *x == eval));

    let mut final_state = state.clone();
    crate::transcript_v09::append_single_last_v09(&mut final_state, eval);
    let gs = crate::transcript_v09::grind_seed_v09(&final_state, params.hash_kind);

    let tg = Instant::now();
    let nonce = if params.g == 0 {
        None
    } else {
        Some(crate::transcript_v09::find_grind_nonce_v09(
            &gs,
            params.g,
            params.hash_kind,
        ))
    };
    let grind = tg.elapsed();

    let tq = Instant::now();
    let leaves0 = 1usize << (family.n + family.k - 1);
    let q0s = crate::transcript_v09::derive_queries_v09(
        &final_state,
        nonce,
        params.s,
        leaves0,
        params.hash_kind,
    );
    let d0 = params.commit_every.min(family.n);
    let ix0 = source_pair_indices(&q0s, 0, d0);
    let opening0 = tree0.open_pairs(&word0, &ix0);
    let mut fops = Vec::with_capacity(boundaries.len());

    for (j, &b) in boundaries.iter().enumerate() {
        let d = params.commit_every.min(family.n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let known_positions = target_positions(&q0s, b);
        fops.push(committed_trees[j].open_pairs_compact(
            &committed_words[j],
            &ix,
            &known_positions,
        ));
    }
    let query_open = tq.elapsed();

    let body = SparseProofV06 {
        folded_roots: roots,
        eval,
        grind_nonce: nonce,
        opening0,
        folded_openings: fops,
    };

    let proof = SparseProofV09 {
        proof_format_version: crate::transcript_v09::PROOF_FORMAT_VERSION_V09,
        header: header.serialize(),
        body,
    };

    let verify = verify_sparse_v09(params, &commitment, &proof)?;
    let challenges = derive_zs_sparse_v09(params, &commitment, &proof.body.folded_roots)
        .ok_or(VerifyErrorV09::InvalidProof)?;

    Ok(SparseTimingsV09 {
        encode: encode_t,
        commit0,
        fold_total,
        commit_folds,
        query_open,
        grind,
        verify,
        commitment,
        proof,
        verified: true,
        challenges,
    })
}

#[cfg(test)]
mod v09_transcript_tests {
    use super::*;
    use crate::{
        security::soundness_bits_from,
        transcript_v09::{ParamsV09, PROOF_FORMAT_VERSION_V09},
    };

    fn required_s(n: usize, k: usize, i0: usize, g: u32, target: u32) -> usize {
        soundness_bits_from(n, k, 128.0, 256.0, g as f64, (target - 128) as f64, i0).s
    }

    fn params_for(
        n: usize,
        k: usize,
        i0: usize,
        g: u32,
        t: usize,
        commit_every: usize,
        seed: u64,
        setup_counter: u64,
    ) -> ParamsV09 {
        ParamsV09 {
            n,
            k,
            i0,
            s: required_s(n, k, i0, g, 192),
            g,
            t,
            commit_every,
            gate_seed: seed,
            setup_counter,
            hash_kind: HashKind::Blake3,
            target_bits: 192,
        }
    }

    fn coeffs(n: usize) -> Vec<F128> {
        (0..(1usize << n)).map(|i| F128((i as u128) + 1)).collect()
    }

    fn make_single(n: usize) -> (ParamsV09, SparseTimingsV09) {
        let seed = 0xA11CEu64 + n as u64;
        let k = 2usize;
        let checked = GateFamily::from_seed_checked_i0_3(n, k, seed);
        let p = params_for(n, k, 3, 0, 1, 3.min(n), seed, checked.counter);
        let run = prove_and_verify_sparse_v09(&coeffs(n), &checked.family, &p).unwrap();
        (p, run)
    }

    #[test]
    fn v09_round_trip_single_n8_n10_n12() {
        for n in [8usize, 10, 12] {
            let (_p, run) = make_single(n);
            assert!(run.verified, "n={n}");
        }
    }

    #[test]
    fn v09_parameter_mismatch_matrix_rejects() {
        let (p, run) = make_single(8);

        macro_rules! reject_with {
            ($name:literal, $mutator:expr) => {{
                let mut q = p.clone();
                $mutator(&mut q);
                assert!(
                    verify_sparse_v09(&q, &run.commitment, &run.proof).is_err(),
                    "parameter mutation unexpectedly verified: {}",
                    $name
                );
            }};
        }

        reject_with!("n", |q: &mut ParamsV09| q.n += 1);
        reject_with!("k", |q: &mut ParamsV09| q.k += 1);
        reject_with!("i0", |q: &mut ParamsV09| q.i0 = 2);
        reject_with!("s", |q: &mut ParamsV09| q.s += 1);
        reject_with!("g", |q: &mut ParamsV09| q.g = 1);
        reject_with!("t", |q: &mut ParamsV09| q.t = 2);
        reject_with!("schedule", |q: &mut ParamsV09| q.commit_every = 2);
        reject_with!("gate_seed", |q: &mut ParamsV09| q.gate_seed ^= 1);
        reject_with!("setup_counter", |q: &mut ParamsV09| q.setup_counter ^= 1);
    }

    #[test]
    fn v09_domain_separator_corruption_rejected() {
        let (p, run) = make_single(8);
        let mut bad = run.proof.clone();
        assert!(bad.header.len() > 4);
        bad.header[4] ^= 1;
        assert!(matches!(
            verify_sparse_v09(&p, &run.commitment, &bad),
            Err(VerifyErrorV09::HeaderMismatch)
        ));
    }

    #[test]
    fn v09_proof_format_version_rejected_clearly() {
        let (p, run) = make_single(8);
        let mut bad = run.proof.clone();
        bad.proof_format_version = 8;
        assert!(matches!(
            verify_sparse_v09(&p, &run.commitment, &bad),
            Err(VerifyErrorV09::VersionMismatch {
                expected: PROOF_FORMAT_VERSION_V09,
                got: 8,
            })
        ));
    }

    #[test]
    fn v09_header_copy_corruption_rejected() {
        let (p, run) = make_single(8);
        let mut bad = run.proof.clone();
        let i = bad.header.len() / 2;
        bad.header[i] ^= 0x80;
        assert!(matches!(
            verify_sparse_v09(&p, &run.commitment, &bad),
            Err(VerifyErrorV09::HeaderMismatch)
        ));
    }

    #[test]
    fn v08_body_wrapped_as_v09_is_rejected_by_version() {
        let n = 8usize;
        let k = 2usize;
        let seed = 0x808u64;
        let checked = GateFamily::from_seed_checked_i0_3(n, k, seed);
        let p = params_for(n, k, 3, 0, 1, 3, seed, checked.counter);

        let old = prove_and_verify_sparse_v06(
            &coeffs(n),
            &checked.family,
            seed,
            checked.counter,
            p.s,
            p.g,
            p.commit_every,
            p.hash_kind,
        );
        assert!(old.verified);

        let wrapped = SparseProofV09 {
            proof_format_version: 8,
            header: Vec::new(),
            body: old.proof,
        };

        assert!(matches!(
            verify_sparse_v09(&p, &old.commitment, &wrapped),
            Err(VerifyErrorV09::VersionMismatch {
                expected: PROOF_FORMAT_VERSION_V09,
                got: 8,
            })
        ));
    }
}

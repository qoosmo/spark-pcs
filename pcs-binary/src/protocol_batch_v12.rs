#![allow(clippy::needless_range_loop, clippy::too_many_arguments)]
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    encode::{derive_gate_level_key, derive_raw_gate_from_level_key, encode, GateFamily},
    extfield::F256,
    field::{batch_inverse, F128},
    gates::Gate,
    merkle_v05::{Hash, HashKind},
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct BatchOpening128 {
    pub values: Vec<F128>,
    pub auth: Vec<Hash>,
}
impl BatchOpening128 {
    pub fn field_bytes(&self) -> usize {
        self.values.len() * 16
    }
    pub fn hash_bytes(&self) -> usize {
        self.auth.len() * 32
    }
    pub fn serialized_size_bytes(&self) -> usize {
        self.field_bytes() + self.hash_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct BatchCompactOpening256 {
    pub values: Vec<F256>,
    pub auth: Vec<Hash>,
}
impl BatchCompactOpening256 {
    pub fn field_bytes(&self) -> usize {
        self.values.len() * 32
    }
    pub fn hash_bytes(&self) -> usize {
        self.auth.len() * 32
    }
    pub fn serialized_size_bytes(&self) -> usize {
        self.field_bytes() + self.hash_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct BatchProofV12 {
    pub folded_roots: Vec<Hash>,
    /// Each value canonically represents the constant final word of one component.
    /// The complete vector is absorbed before grinding/query derivation.
    pub evals: Vec<F256>,
    pub grind_nonce: Option<u64>,
    pub opening0: BatchOpening128,
    pub folded_openings: Vec<BatchCompactOpening256>,
}
impl BatchProofV12 {
    pub fn field_bytes(&self) -> usize {
        self.evals.len() * 32
            + self.opening0.field_bytes()
            + self
                .folded_openings
                .iter()
                .map(|x| x.field_bytes())
                .sum::<usize>()
    }
    pub fn hash_bytes(&self) -> usize {
        self.folded_roots.len() * 32
            + self.opening0.hash_bytes()
            + self
                .folded_openings
                .iter()
                .map(|x| x.hash_bytes())
                .sum::<usize>()
    }
    pub fn serialized_size_bytes(&self) -> usize {
        self.field_bytes() + self.hash_bytes() + self.grind_nonce.map(|_| 8).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BatchVerifyProfile {
    pub transcript: Duration,
    pub gate_derivation: Duration,
    pub gate_prf: Duration,
    pub gate_batch_inverse: Duration,
    pub gate_build: Duration,
    pub merkle: Duration,
    pub folding: Duration,
    pub other: Duration,
}
impl BatchVerifyProfile {
    pub fn total(&self) -> Duration {
        self.transcript + self.gate_derivation + self.merkle + self.folding + self.other
    }
    pub fn checks(&self) -> Duration {
        self.transcript + self.merkle + self.folding + self.other
    }
}

#[derive(Debug)]
pub struct BatchTimingsV12 {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub grind: Duration,
    pub verify: BatchVerifyProfile,
    pub commitment: Hash,
    pub proof: BatchProofV12,
    pub verified: bool,
    pub challenges: Vec<F256>,
    pub peak_memory_estimate_bytes: usize,
}
impl BatchTimingsV12 {
    pub fn prover_total(&self) -> Duration {
        self.encode
            + self.commit0
            + self.fold_total
            + self.commit_folds
            + self.query_open
            + self.grind
    }
}

fn hash_parts(kind: HashKind, parts: &[&[u8]]) -> Hash {
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
#[inline]
fn h_node(kind: HashKind, l: &Hash, r: &Hash) -> Hash {
    match kind {
        HashKind::Blake3 => {
            const DOMAIN: &[u8] = b"SPARK-BINARY-NODE-v0.5";
            let mut buf = [0u8; 96];
            let mut off = 0usize;
            buf[off..off + DOMAIN.len()].copy_from_slice(DOMAIN);
            off += DOMAIN.len();
            buf[off..off + 32].copy_from_slice(l);
            off += 32;
            buf[off..off + 32].copy_from_slice(r);
            off += 32;
            *blake3::hash(&buf[..off]).as_bytes()
        }
        HashKind::Sha256 => hash_parts(kind, &[b"SPARK-BINARY-NODE-v0.5", l, r]),
    }
}
#[inline]
fn single_leaf128(kind: HashKind, a: F128, b: F128) -> Hash {
    let ab = a.to_le_bytes();
    let bb = b.to_le_bytes();
    hash_parts(kind, &[b"SPARK-BINARY-LEAF-v0.5", &ab, &bb])
}
#[inline]
fn single_leaf256(kind: HashKind, a: F256, b: F256) -> Hash {
    let ab = a.to_le_bytes();
    let bb = b.to_le_bytes();
    hash_parts(kind, &[b"SPARK-BINARY-LEAF-v0.5", &ab, &bb])
}
fn batch_leaf128(kind: HashKind, pairs: &[[F128; 2]]) -> Hash {
    if pairs.len() == 1 {
        return single_leaf128(kind, pairs[0][0], pairs[0][1]);
    }
    match kind {
        HashKind::Blake3 => {
            let mut h = blake3::Hasher::new();
            h.update(b"SPARK-BATCH-LEAF-v1");
            h.update(&(pairs.len() as u64).to_le_bytes());
            for p in pairs {
                h.update(&p[0].to_le_bytes());
                h.update(&p[1].to_le_bytes());
            }
            *h.finalize().as_bytes()
        }
        HashKind::Sha256 => {
            let mut h = Sha256::new();
            h.update(b"SPARK-BATCH-LEAF-v1");
            h.update((pairs.len() as u64).to_le_bytes());
            for p in pairs {
                h.update(p[0].to_le_bytes());
                h.update(p[1].to_le_bytes());
            }
            h.finalize().into()
        }
    }
}
fn batch_leaf256(kind: HashKind, pairs: &[[F256; 2]]) -> Hash {
    if pairs.len() == 1 {
        return single_leaf256(kind, pairs[0][0], pairs[0][1]);
    }
    match kind {
        HashKind::Blake3 => {
            let mut h = blake3::Hasher::new();
            h.update(b"SPARK-BATCH-LEAF-v1");
            h.update(&(pairs.len() as u64).to_le_bytes());
            for p in pairs {
                h.update(&p[0].to_le_bytes());
                h.update(&p[1].to_le_bytes());
            }
            *h.finalize().as_bytes()
        }
        HashKind::Sha256 => {
            let mut h = Sha256::new();
            h.update(b"SPARK-BATCH-LEAF-v1");
            h.update((pairs.len() as u64).to_le_bytes());
            for p in pairs {
                h.update(p[0].to_le_bytes());
                h.update(p[1].to_le_bytes());
            }
            h.finalize().into()
        }
    }
}

#[derive(Clone, Debug)]
struct BatchMerkleTree {
    levels: Vec<Vec<Hash>>,
}
impl BatchMerkleTree {
    fn from_leaf_hashes(leaves: Vec<Hash>, kind: HashKind) -> Self {
        assert!(leaves.len().is_power_of_two() && !leaves.is_empty());
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .par_chunks_exact(2)
                .map(|p| h_node(kind, &p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        Self { levels }
    }
    fn from_base(words: &[Vec<F128>], kind: HashKind) -> Self {
        assert!(!words.is_empty());
        let n = words[0].len();
        assert!(n.is_power_of_two() && n >= 2);
        assert!(words.iter().all(|w| w.len() == n));
        let leaves = (0..n / 2)
            .into_par_iter()
            .map(|i| {
                let pairs = words
                    .iter()
                    .map(|w| [w[2 * i], w[2 * i + 1]])
                    .collect::<Vec<_>>();
                batch_leaf128(kind, &pairs)
            })
            .collect();
        Self::from_leaf_hashes(leaves, kind)
    }
    fn from_ext(words: &[Vec<F256>], kind: HashKind) -> Self {
        assert!(!words.is_empty());
        let n = words[0].len();
        assert!(n.is_power_of_two() && n >= 2);
        assert!(words.iter().all(|w| w.len() == n));
        let leaves = (0..n / 2)
            .into_par_iter()
            .map(|i| {
                let pairs = words
                    .iter()
                    .map(|w| [w[2 * i], w[2 * i + 1]])
                    .collect::<Vec<_>>();
                batch_leaf256(kind, &pairs)
            })
            .collect();
        Self::from_leaf_hashes(leaves, kind)
    }
    fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }
    fn auth(&self, indices: &[usize]) -> Vec<Hash> {
        let mut auth = Vec::new();
        let mut cur = indices.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            for &idx in &cur {
                let sib = idx ^ 1;
                if cur.binary_search(&sib).is_err() {
                    auth.push(level[sib]);
                }
            }
            cur = cur.into_iter().map(|i| i >> 1).collect();
            cur.dedup();
        }
        auth
    }
    fn open_base(&self, words: &[Vec<F128>], indices: &[usize]) -> BatchOpening128 {
        let t = words.len();
        let mut values = Vec::with_capacity(indices.len() * 2 * t);
        for &i in indices {
            for w in words {
                values.push(w[2 * i]);
                values.push(w[2 * i + 1]);
            }
        }
        BatchOpening128 {
            values,
            auth: self.auth(indices),
        }
    }
    fn open_ext_compact(
        &self,
        words: &[Vec<F256>],
        indices: &[usize],
        known_positions: &[usize],
    ) -> BatchCompactOpening256 {
        let mut values = Vec::new();
        for &i in indices {
            for pos in [2 * i, 2 * i + 1] {
                if known_positions.binary_search(&pos).is_err() {
                    for w in words {
                        values.push(w[pos]);
                    }
                }
            }
        }
        BatchCompactOpening256 {
            values,
            auth: self.auth(indices),
        }
    }
}

fn verify_frontier(
    root: &Hash,
    leaf_count: usize,
    indices: &[usize],
    leaf_hashes: Vec<Hash>,
    auth: &[Hash],
    kind: HashKind,
) -> bool {
    if !leaf_count.is_power_of_two() || indices.is_empty() || indices.len() != leaf_hashes.len() {
        return false;
    }
    if *indices.last().unwrap() >= leaf_count || !indices.windows(2).all(|w| w[0] < w[1]) {
        return false;
    }
    let mut cur = indices.iter().copied().zip(leaf_hashes).collect::<Vec<_>>();
    let mut next = Vec::new();
    let mut ap = 0usize;
    for _ in 0..leaf_count.trailing_zeros() {
        next.clear();
        let mut i = 0usize;
        while i < cur.len() {
            let (idx, h) = cur[i];
            let (l, r);
            if idx & 1 == 0 && i + 1 < cur.len() && cur[i + 1].0 == idx + 1 {
                l = h;
                r = cur[i + 1].1;
                i += 2;
            } else {
                if ap >= auth.len() {
                    return false;
                }
                let sib = auth[ap];
                ap += 1;
                if idx & 1 == 0 {
                    l = h;
                    r = sib
                } else {
                    l = sib;
                    r = h
                };
                i += 1;
            }
            next.push((idx >> 1, h_node(kind, &l, &r)));
        }
        std::mem::swap(&mut cur, &mut next);
    }
    ap == auth.len() && cur.len() == 1 && cur[0].0 == 0 && cur[0].1 == *root
}

fn verify_base_opening(
    root: &Hash,
    leaf_count: usize,
    indices: &[usize],
    op: &BatchOpening128,
    t: usize,
    kind: HashKind,
) -> Option<Vec<Vec<[F128; 2]>>> {
    if op.values.len() != indices.len() * 2 * t {
        return None;
    }
    let mut vp = 0usize;
    let mut by_comp = (0..t)
        .map(|_| Vec::with_capacity(indices.len()))
        .collect::<Vec<_>>();
    let mut hashes = Vec::with_capacity(indices.len());
    for _ in indices {
        let mut pairs = Vec::with_capacity(t);
        for c in 0..t {
            let p = [op.values[vp], op.values[vp + 1]];
            vp += 2;
            by_comp[c].push(p);
            pairs.push(p);
        }
        hashes.push(batch_leaf128(kind, &pairs));
    }
    if verify_frontier(root, leaf_count, indices, hashes, &op.auth, kind) {
        Some(by_comp)
    } else {
        None
    }
}

fn verify_ext_compact(
    root: &Hash,
    leaf_count: usize,
    indices: &[usize],
    known: &[HashMap<usize, F256>],
    op: &BatchCompactOpening256,
    t: usize,
    kind: HashKind,
) -> Option<Vec<Vec<[F256; 2]>>> {
    if known.len() != t {
        return None;
    }
    let mut vp = 0usize;
    let mut by_comp = (0..t)
        .map(|_| Vec::with_capacity(indices.len()))
        .collect::<Vec<_>>();
    let mut hashes = Vec::with_capacity(indices.len());
    for &i in indices {
        let mut pairs = vec![[F256::ZERO; 2]; t];
        for (side, pos) in [(0usize, 2 * i), (1usize, 2 * i + 1)] {
            let is_known = known[0].contains_key(&pos);
            if known.iter().any(|m| m.contains_key(&pos) != is_known) {
                return None;
            }
            if is_known {
                for c in 0..t {
                    pairs[c][side] = *known[c].get(&pos)?;
                }
            } else {
                if vp + t > op.values.len() {
                    return None;
                }
                for c in 0..t {
                    pairs[c][side] = op.values[vp];
                    vp += 1;
                }
            }
        }
        hashes.push(batch_leaf256(kind, &pairs));
        for c in 0..t {
            by_comp[c].push(pairs[c]);
        }
    }
    if vp != op.values.len() {
        return None;
    }
    if verify_frontier(root, leaf_count, indices, hashes, &op.auth, kind) {
        Some(by_comp)
    } else {
        None
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
fn derive_zs(
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
    let mut ri = 0;
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
fn query_transcript(
    commitment: &Hash,
    roots: &[Hash],
    evals: &[F256],
    commit_every: usize,
) -> Vec<u8> {
    let mut st = init_state(commitment, commit_every);
    for r in roots {
        st.extend_from_slice(r);
    }
    if evals.len() == 1 {
        st.extend_from_slice(&evals[0].to_le_bytes());
    } else {
        st.extend_from_slice(b"SPARK-BATCH-LAST-v1");
        st.extend_from_slice(&(evals.len() as u64).to_le_bytes());
        for e in evals {
            st.extend_from_slice(&e.to_le_bytes());
        }
    }
    st
}
fn leading_zero_bits(d: &Hash) -> u32 {
    let mut z = 0;
    for &b in d {
        if b == 0 {
            z += 8
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
    evals: &[F256],
    commit_every: usize,
    kind: HashKind,
) -> Hash {
    let st = query_transcript(commitment, roots, evals, commit_every);
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
    let mut start: u64 = 0;
    loop {
        let end = start.checked_add(CHUNK).expect("grinding nonce overflow");
        if let Some(n) = (start..end)
            .into_par_iter()
            .filter(|&x| valid_grind_nonce(seed, x, bits, kind))
            .min()
        {
            return n;
        }
        start = end;
    }
}
pub fn derive_batch_queries(
    commitment: &Hash,
    roots: &[Hash],
    evals: &[F256],
    nonce: Option<u64>,
    s: usize,
    leaves: usize,
    commit_every: usize,
    kind: HashKind,
) -> Vec<usize> {
    let mut st = query_transcript(commitment, roots, evals, commit_every);
    if let Some(n) = nonce {
        st.extend_from_slice(b"SPARK-GRIND-NONCE-SPARSE-v0.6");
        st.extend_from_slice(&n.to_le_bytes());
    }
    (0..s)
        .map(|i| challenge_index(&st, i as u64, leaves, kind))
        .collect()
}

#[inline]
fn fold_first_lambda(lambda: F256, w0: F128, w1: F128) -> F256 {
    F256::from_base(w0) + lambda.mul_base(w1 + w0)
}
#[inline]
fn fold_ext_lambda(lambda: F256, w0: F256, w1: F256) -> F256 {
    w0 + lambda * (w1 + w0)
}
fn fold_first_level(word: &[F128], gates: &[Gate], z: F256) -> Vec<F256> {
    word.par_chunks_exact(2)
        .zip(gates.par_iter().copied())
        .map(|(w, g)| {
            let l = (z + F256::from_base(g.t0)).mul_base(g.inv_dt);
            fold_first_lambda(l, w[0], w[1])
        })
        .collect()
}
fn fold_ext_level(word: &[F256], gates: &[Gate], z: F256) -> Vec<F256> {
    word.par_chunks_exact(2)
        .zip(gates.par_iter().copied())
        .map(|(w, g)| {
            let l = (z + F256::from_base(g.t0)).mul_base(g.inv_dt);
            fold_ext_lambda(l, w[0], w[1])
        })
        .collect()
}
fn source_pair_indices(q0s: &[usize], a: usize, d: usize) -> Vec<usize> {
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
    let mut out = q0s.iter().map(|q| q >> (b - 1)).collect::<Vec<_>>();
    out.sort_unstable();
    out.dedup();
    out
}
fn collect_gate_keys(n: usize, q0s: &[usize], commit_every: usize) -> Vec<(usize, usize)> {
    let mut keys = Vec::new();
    let mut a = 0;
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
            for x in 0..d {
                let ps = start_word >> (x + 1);
                for j in 0..len / 2 {
                    keys.push((n - 1 - (a + x), ps + j));
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
fn derive_sparse_gates(
    seed: u64,
    setup_counter: u64,
    keys: &[(usize, usize)],
) -> (Vec<Gate>, Duration, Duration, Duration) {
    let t0 = Instant::now();
    let mut raw = Vec::with_capacity(keys.len());
    let mut cur = None;
    let mut lk = [0u8; 32];
    for &(level, node) in keys {
        if cur != Some(level) {
            lk = derive_gate_level_key(seed, setup_counter, level);
            cur = Some(level);
        }
        raw.push(derive_raw_gate_from_level_key(&lk, node));
    }
    let prf = t0.elapsed();
    let den = raw.iter().map(|(a, b)| *a + *b).collect::<Vec<_>>();
    let ti = Instant::now();
    let inv = batch_inverse(&den);
    let inv_t = ti.elapsed();
    let tb = Instant::now();
    let gates = raw
        .into_iter()
        .zip(inv)
        .map(|((a, b), iv)| Gate::new(a, b, iv))
        .collect();
    (gates, prf, inv_t, tb.elapsed())
}
fn derive_lambdas(n: usize, keys: &[(usize, usize)], gates: &[Gate], zs: &[F256]) -> Vec<F256> {
    keys.iter()
        .zip(gates.iter().copied())
        .map(|(&(level, _), g)| {
            let round = n - 1 - level;
            (zs[round] + F256::from_base(g.t0)).mul_base(g.inv_dt)
        })
        .collect()
}
fn lambda_at(keys: &[(usize, usize)], ls: &[F256], level: usize, node: usize) -> Option<F256> {
    keys.binary_search(&(level, node)).ok().map(|i| ls[i])
}
fn pair_at<T: Copy>(indices: &[usize], pairs: &[[T; 2]], p: usize) -> Option<[T; 2]> {
    indices.binary_search(&p).ok().map(|i| pairs[i])
}
fn fold_block_first(
    n: usize,
    d: usize,
    base: usize,
    indices: &[usize],
    pairs: &[[F128; 2]],
    keys: &[(usize, usize)],
    ls: &[F256],
) -> Option<F256> {
    let width = 1usize << (d - 1);
    let mut cur = Vec::with_capacity(width);
    for p in base..base + width {
        let v = pair_at(indices, pairs, p)?;
        let l = lambda_at(keys, ls, n - 1, p)?;
        cur.push(fold_first_lambda(l, v[0], v[1]));
    }
    let start = 2 * base;
    for x in 1..d {
        let ps = start >> (x + 1);
        cur = cur
            .chunks_exact(2)
            .enumerate()
            .map(|(j, w)| {
                let l = lambda_at(keys, ls, n - 1 - x, ps + j).expect("lambda");
                fold_ext_lambda(l, w[0], w[1])
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
    keys: &[(usize, usize)],
    ls: &[F256],
) -> Option<F256> {
    let width = 1usize << (d - 1);
    let mut cur = Vec::with_capacity(1usize << d);
    for p in base..base + width {
        let v = pair_at(indices, pairs, p)?;
        cur.push(v[0]);
        cur.push(v[1]);
    }
    let start = 2 * base;
    for x in 0..d {
        let ps = start >> (x + 1);
        cur = cur
            .chunks_exact(2)
            .enumerate()
            .map(|(j, w)| {
                let l = lambda_at(keys, ls, n - 1 - (a + x), ps + j).expect("lambda");
                fold_ext_lambda(l, w[0], w[1])
            })
            .collect();
    }
    cur.first().copied()
}
fn known_first(
    n: usize,
    d: usize,
    q0s: &[usize],
    indices: &[usize],
    pairs: &[Vec<[F128; 2]>],
    keys: &[(usize, usize)],
    ls: &[F256],
) -> Option<Vec<HashMap<usize, F256>>> {
    let width = 1usize << (d - 1);
    let mut out = (0..pairs.len()).map(|_| HashMap::new()).collect::<Vec<_>>();
    for c in 0..pairs.len() {
        for &q in q0s {
            let pos = q >> (d - 1);
            if out[c].contains_key(&pos) {
                continue;
            }
            let base = (q / width) * width;
            out[c].insert(
                pos,
                fold_block_first(n, d, base, indices, &pairs[c], keys, ls)?,
            );
        }
    }
    Some(out)
}
fn known_ext(
    n: usize,
    a: usize,
    d: usize,
    q0s: &[usize],
    indices: &[usize],
    pairs: &[Vec<[F256; 2]>],
    keys: &[(usize, usize)],
    ls: &[F256],
) -> Option<Vec<HashMap<usize, F256>>> {
    let width = 1usize << (d - 1);
    let mut out = (0..pairs.len()).map(|_| HashMap::new()).collect::<Vec<_>>();
    for c in 0..pairs.len() {
        for &q in q0s {
            let pos = q >> (a + d - 1);
            if out[c].contains_key(&pos) {
                continue;
            }
            let p = q >> a;
            let base = (p / width) * width;
            out[c].insert(
                pos,
                fold_block_ext(n, a, d, base, indices, &pairs[c], keys, ls)?,
            );
        }
    }
    Some(out)
}

pub fn verify_batch_v12(
    seed: u64,
    setup_counter: u64,
    n: usize,
    k: usize,
    commitment: &Hash,
    proof: &BatchProofV12,
    batch_t: usize,
    s: usize,
    grind_bits: u32,
    commit_every: usize,
    kind: HashKind,
) -> (bool, BatchVerifyProfile) {
    let total = Instant::now();
    let mut prof = BatchVerifyProfile::default();
    if n == 0
        || s == 0
        || batch_t == 0
        || proof.evals.len() != batch_t
        || commit_every == 0
        || commit_every > n
        || grind_bits > 32
    {
        return (false, prof);
    }
    let tr = Instant::now();
    let boundaries = committed_boundaries(n, commit_every);
    if proof.folded_roots.len() != boundaries.len()
        || proof.folded_openings.len() != boundaries.len()
    {
        prof.transcript = tr.elapsed();
        return (false, prof);
    }
    let zs = match derive_zs(commitment, &proof.folded_roots, n, commit_every, kind) {
        Some(x) => x,
        None => return (false, prof),
    };
    let leaves0 = 1usize << (n + k - 1);
    let gs = grind_seed(
        commitment,
        &proof.folded_roots,
        &proof.evals,
        commit_every,
        kind,
    );
    let nonce = match (grind_bits, proof.grind_nonce) {
        (0, None) => None,
        (0, Some(_)) => return (false, prof),
        (_, Some(x)) if valid_grind_nonce(&gs, x, grind_bits, kind) => Some(x),
        _ => return (false, prof),
    };
    let q0s = derive_batch_queries(
        commitment,
        &proof.folded_roots,
        &proof.evals,
        nonce,
        s,
        leaves0,
        commit_every,
        kind,
    );
    let keys = collect_gate_keys(n, &q0s, commit_every);
    prof.transcript = tr.elapsed();
    let gd = Instant::now();
    let (gates, p, i, b) = derive_sparse_gates(seed, setup_counter, &keys);
    prof.gate_derivation = gd.elapsed();
    prof.gate_prf = p;
    prof.gate_batch_inverse = i;
    prof.gate_build = b;
    let ft = Instant::now();
    let ls = derive_lambdas(n, &keys, &gates, &zs);
    prof.folding += ft.elapsed();

    let d0 = commit_every.min(n);
    let ix0 = source_pair_indices(&q0s, 0, d0);
    let mt = Instant::now();
    let pairs0 = verify_base_opening(commitment, leaves0, &ix0, &proof.opening0, batch_t, kind);
    prof.merkle += mt.elapsed();
    let pairs0 = match pairs0 {
        Some(x) => x,
        None => return (false, prof),
    };
    let ft = Instant::now();
    let mut known = match known_first(n, d0, &q0s, &ix0, &pairs0, &keys, &ls) {
        Some(x) => x,
        None => return (false, prof),
    };
    prof.folding += ft.elapsed();
    let mut a = d0;
    for (j, &bound) in boundaries.iter().enumerate() {
        if bound != a {
            return (false, prof);
        }
        let d = commit_every.min(n - bound);
        let ix = source_pair_indices(&q0s, bound, d);
        let leaves = leaves0 >> bound;
        let mt = Instant::now();
        let pairs = verify_ext_compact(
            &proof.folded_roots[j],
            leaves,
            &ix,
            &known,
            &proof.folded_openings[j],
            batch_t,
            kind,
        );
        prof.merkle += mt.elapsed();
        let pairs = match pairs {
            Some(x) => x,
            None => return (false, prof),
        };
        let ft = Instant::now();
        known = match known_ext(n, bound, d, &q0s, &ix, &pairs, &keys, &ls) {
            Some(x) => x,
            None => return (false, prof),
        };
        prof.folding += ft.elapsed();
        a = bound + d;
    }
    let ok = a == n && (0..batch_t).all(|c| known[c].values().all(|v| *v == proof.evals[c]));
    let accounted = prof.transcript + prof.gate_derivation + prof.merkle + prof.folding;
    prof.other = total
        .elapsed()
        .checked_sub(accounted)
        .unwrap_or(Duration::ZERO);
    (ok, prof)
}

fn direct_eval(coeffs: &[F128], zs: &[F256]) -> F256 {
    // SPARK coefficient order: x_n is the least-significant bit.
    // Challenges are ordered (r_1,...,r_n), so coefficient bit j
    // corresponds to challenge r_{n-j}.
    let n = zs.len();
    let mut acc = F256::ZERO;
    for (mask, &a) in coeffs.iter().enumerate() {
        let mut term = F256::from_base(a);
        for bit in 0..n {
            if ((mask >> bit) & 1) == 1 {
                term *= zs[n - 1 - bit];
            }
        }
        acc += term;
    }
    acc
}
pub fn evaluate_coefficients_at_challenges(coeffs: &[F128], zs: &[F256]) -> F256 {
    direct_eval(coeffs, zs)
}

pub fn prove_and_verify_batch_v12(
    coeff_batches: &[Vec<F128>],
    family: &GateFamily,
    seed: u64,
    setup_counter: u64,
    s: usize,
    grind_bits: u32,
    commit_every: usize,
    kind: HashKind,
) -> BatchTimingsV12 {
    assert!(!coeff_batches.is_empty());
    assert!(commit_every >= 1 && commit_every <= family.n);
    let bt = coeff_batches.len();
    let coeff_len = 1usize << family.n;
    assert!(coeff_batches.iter().all(|c| c.len() == coeff_len));
    let stream = bt >= 32;
    let te = Instant::now();
    let mut word0s = coeff_batches
        .iter()
        .map(|c| encode(c, family))
        .collect::<Vec<_>>();
    let mut encode_t = te.elapsed();
    let tc = Instant::now();
    let tree0 = BatchMerkleTree::from_base(&word0s, kind);
    let commitment = tree0.root();
    let commit0 = tc.elapsed();

    let boundaries = committed_boundaries(family.n, commit_every);
    let mut roots = Vec::with_capacity(boundaries.len());
    let mut committed_words = Vec::<Vec<Vec<F256>>>::with_capacity(boundaries.len());
    let mut committed_trees = Vec::<BatchMerkleTree>::with_capacity(boundaries.len());
    let mut state = init_state(&commitment, commit_every);
    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;
    let mut current = Vec::<Vec<F256>>::new();
    let mut final_words = Vec::<Vec<F256>>::new();

    for (r, level) in family.levels.iter().rev().enumerate() {
        let z = challenge_field(&state, b"fold", r as u64, kind);
        let tf = Instant::now();
        if r == 0 {
            if stream {
                word0s.clear();
                word0s.shrink_to_fit();
                let re = Instant::now();
                current = coeff_batches
                    .iter()
                    .map(|c| {
                        let w = encode(c, family);
                        fold_first_level(&w, &level.gates, z)
                    })
                    .collect();
                encode_t += re.elapsed();
            } else {
                current = word0s
                    .iter()
                    .map(|w| fold_first_level(w, &level.gates, z))
                    .collect();
            }
        } else {
            for c in 0..current.len() {
                let next = fold_ext_level(&current[c], &level.gates, z);
                current[c] = next;
            }
        }
        fold_total += tf.elapsed();
        let b = r + 1;
        if b < family.n && b % commit_every == 0 {
            let tc = Instant::now();
            let tree = BatchMerkleTree::from_ext(&current, kind);
            let root = tree.root();
            commit_folds += tc.elapsed();
            roots.push(root);
            state.extend_from_slice(&root);
            committed_words.push(current.clone());
            committed_trees.push(tree);
        } else if b < family.n {
            state.extend_from_slice(b"SPARK-SKIP-v0.6");
            state.extend_from_slice(&z.to_le_bytes());
        }
        if b == family.n {
            final_words = current.clone();
        }
    }
    let evals = final_words.iter().map(|w| w[0]).collect::<Vec<_>>();
    debug_assert!(final_words.iter().all(|w| w.iter().all(|x| *x == w[0])));
    let gs = grind_seed(&commitment, &roots, &evals, commit_every, kind);
    let tg = Instant::now();
    let nonce = if grind_bits == 0 {
        None
    } else {
        Some(find_grind_nonce(&gs, grind_bits, kind))
    };
    let grind = tg.elapsed();
    let to = Instant::now();
    let leaves0 = 1usize << (family.n + family.k - 1);
    let q0s = derive_batch_queries(
        &commitment,
        &roots,
        &evals,
        nonce,
        s,
        leaves0,
        commit_every,
        kind,
    );
    let d0 = commit_every.min(family.n);
    let ix0 = source_pair_indices(&q0s, 0, d0);
    if stream {
        let re = Instant::now();
        word0s = coeff_batches.iter().map(|c| encode(c, family)).collect();
        encode_t += re.elapsed();
    }
    let opening0 = tree0.open_base(&word0s, &ix0);
    let mut fops = Vec::with_capacity(boundaries.len());
    for (j, &b) in boundaries.iter().enumerate() {
        let d = commit_every.min(family.n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let kp = target_positions(&q0s, b);
        fops.push(committed_trees[j].open_ext_compact(&committed_words[j], &ix, &kp));
    }
    let query_open = to.elapsed();
    let proof = BatchProofV12 {
        folded_roots: roots,
        evals,
        grind_nonce: nonce,
        opening0,
        folded_openings: fops,
    };
    let (verified, verify) = verify_batch_v12(
        seed,
        setup_counter,
        family.n,
        family.k,
        &commitment,
        &proof,
        bt,
        s,
        grind_bits,
        commit_every,
        kind,
    );
    let challenges = derive_zs(
        &commitment,
        &proof.folded_roots,
        family.n,
        commit_every,
        kind,
    )
    .unwrap();

    let nword = 1usize << (family.n + family.k);
    let base_bytes = bt * nword * 16;
    let ext_bytes = bt * (nword / 2) * 32;
    let tree_bytes = (nword / 2) * 2 * 32;
    let committed_est = if commit_every >= usize::BITS as usize {
        0
    } else {
        ext_bytes / ((1usize << commit_every).saturating_sub(1).max(1))
    };
    let peak = if stream {
        base_bytes.max(ext_bytes) + tree_bytes + committed_est
    } else {
        base_bytes + ext_bytes + tree_bytes + committed_est
    };
    BatchTimingsV12 {
        encode: encode_t,
        commit0,
        fold_total,
        commit_folds,
        query_open,
        grind,
        verify,
        commitment,
        proof,
        verified,
        challenges,
        peak_memory_estimate_bytes: peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn coeffs(t: usize, n: usize) -> Vec<Vec<F128>> {
        (0..t)
            .map(|c| {
                (0..1usize << n)
                    .map(|i| F128(1 + (c as u128) * 1000 + i as u128))
                    .collect()
            })
            .collect()
    }
    #[test]
    fn honest_batches_and_evaluations() {
        let seed = 12345;
        let n = 4;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        for &bt in &[1usize, 2, 4, 16] {
            let cs = coeffs(bt, n);
            let run = prove_and_verify_batch_v12(
                &cs,
                &checked.family,
                seed,
                checked.counter,
                16,
                0,
                3,
                HashKind::Blake3,
            );
            assert!(run.verified, "t={bt}");
            for i in 0..bt {
                assert_eq!(
                    run.proof.evals[i],
                    direct_eval(&cs[i], &run.challenges),
                    "t={bt} i={i}"
                );
            }
        }
    }
    #[test]
    fn wrong_component_output_rejected() {
        let seed = 7;
        let n = 4;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let cs = coeffs(4, n);
        let run = prove_and_verify_batch_v12(
            &cs,
            &checked.family,
            seed,
            checked.counter,
            16,
            0,
            3,
            HashKind::Blake3,
        );
        assert!(run.verified);
        let mut bad = run.proof.clone();
        bad.evals[2] += F256::ONE;
        assert!(
            !verify_batch_v12(
                seed,
                checked.counter,
                n,
                k,
                &run.commitment,
                &bad,
                4,
                16,
                0,
                3,
                HashKind::Blake3
            )
            .0
        );
    }
    #[test]
    fn corrupted_component_opening_rejected() {
        let seed = 8;
        let n = 4;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let cs = coeffs(4, n);
        let run = prove_and_verify_batch_v12(
            &cs,
            &checked.family,
            seed,
            checked.counter,
            16,
            0,
            3,
            HashKind::Blake3,
        );
        assert!(run.verified);
        let mut bad = run.proof.clone();
        bad.opening0.values[2] += F128(1);
        assert!(
            !verify_batch_v12(
                seed,
                checked.counter,
                n,
                k,
                &run.commitment,
                &bad,
                4,
                16,
                0,
                3,
                HashKind::Blake3
            )
            .0
        );
    }
    #[test]
    fn corrupted_folded_component_rejected() {
        let seed = 9;
        let n = 6;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let cs = coeffs(4, n);
        let run = prove_and_verify_batch_v12(
            &cs,
            &checked.family,
            seed,
            checked.counter,
            24,
            0,
            3,
            HashKind::Blake3,
        );
        assert!(run.verified);
        let mut bad = run.proof.clone();
        if !bad.folded_openings[0].values.is_empty() {
            bad.folded_openings[0].values[0] += F256::ONE;
        } else {
            panic!("expected explicit folded value");
        }
        assert!(
            !verify_batch_v12(
                seed,
                checked.counter,
                n,
                k,
                &run.commitment,
                &bad,
                4,
                24,
                0,
                3,
                HashKind::Blake3
            )
            .0
        );
    }
    #[test]
    fn last_layer_binds_queries() {
        let seed = 10;
        let n = 4;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let cs = coeffs(4, n);
        let run = prove_and_verify_batch_v12(
            &cs,
            &checked.family,
            seed,
            checked.counter,
            32,
            0,
            3,
            HashKind::Blake3,
        );
        let leaves = 1usize << (n + k - 1);
        let q1 = derive_batch_queries(
            &run.commitment,
            &run.proof.folded_roots,
            &run.proof.evals,
            None,
            32,
            leaves,
            3,
            HashKind::Blake3,
        );
        let mut e = run.proof.evals.clone();
        e[1] += F256::ONE;
        let q2 = derive_batch_queries(
            &run.commitment,
            &run.proof.folded_roots,
            &e,
            None,
            32,
            leaves,
            3,
            HashKind::Blake3,
        );
        assert_ne!(q1, q2);
    }
    #[test]
    fn t1_proof_size_matches_single_sparse() {
        use crate::protocol_sparse_v06::prove_and_verify_sparse_v06;
        let seed = 11;
        let n = 6;
        let k = 2;
        let checked = GateFamily::from_seed_checked(n, k, seed);
        let cs = coeffs(1, n);
        let a = prove_and_verify_batch_v12(
            &cs,
            &checked.family,
            seed,
            checked.counter,
            16,
            0,
            3,
            HashKind::Blake3,
        );
        let b = prove_and_verify_sparse_v06(
            &cs[0],
            &checked.family,
            seed,
            checked.counter,
            16,
            0,
            3,
            HashKind::Blake3,
        );
        assert!(a.verified && b.verified);
        assert_eq!(
            a.proof.serialized_size_bytes(),
            b.proof.serialized_size_bytes()
        );
        assert_eq!(a.commitment, b.commitment);
        assert_eq!(a.proof.evals[0], b.proof.eval);
    }
}

// -----------------------------------------------------------------------------
// SPARK v0.9 batch transcript wrapper.
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct BatchProofV09 {
    pub proof_format_version: u8,
    pub header: Vec<u8>,
    pub body: BatchProofV12,
}

impl BatchProofV09 {
    pub fn serialized_size_bytes(&self) -> usize {
        1 + 4 + self.header.len() + self.body.serialized_size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchVerifyErrorV09 {
    VersionMismatch { expected: u8, got: u8 },
    InvalidParams(String),
    HeaderMismatch,
    InvalidProof,
}

#[derive(Debug)]
pub struct BatchTimingsV09 {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub grind: Duration,
    pub verify: BatchVerifyProfile,
    pub commitment: Hash,
    pub proof: BatchProofV09,
    pub verified: bool,
    pub challenges: Vec<F256>,
    pub peak_memory_estimate_bytes: usize,
}

impl BatchTimingsV09 {
    pub fn prover_total(&self) -> Duration {
        self.encode
            + self.commit0
            + self.fold_total
            + self.commit_folds
            + self.query_open
            + self.grind
    }
}

fn derive_zs_batch_v09(
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

fn final_state_batch_v09(
    params: &crate::transcript_v09::ParamsV09,
    commitment: &Hash,
    roots: &[Hash],
    evals: &[F256],
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
    crate::transcript_v09::append_batch_last_v09(&mut st, evals);
    Some(st)
}

pub fn verify_batch_v09(
    params: &crate::transcript_v09::ParamsV09,
    commitment: &Hash,
    proof: &BatchProofV09,
) -> Result<BatchVerifyProfile, BatchVerifyErrorV09> {
    let total = Instant::now();
    let mut prof = BatchVerifyProfile::default();

    params
        .validate()
        .map_err(BatchVerifyErrorV09::InvalidParams)?;

    if proof.proof_format_version != crate::transcript_v09::PROOF_FORMAT_VERSION_V09 {
        return Err(BatchVerifyErrorV09::VersionMismatch {
            expected: crate::transcript_v09::PROOF_FORMAT_VERSION_V09,
            got: proof.proof_format_version,
        });
    }

    let expected_header = params
        .header()
        .map_err(BatchVerifyErrorV09::InvalidParams)?
        .serialize();
    if proof.header != expected_header {
        return Err(BatchVerifyErrorV09::HeaderMismatch);
    }
    if proof.body.evals.len() != params.t {
        return Err(BatchVerifyErrorV09::InvalidProof);
    }

    let tr = Instant::now();
    let boundaries = committed_boundaries(params.n, params.commit_every);
    if proof.body.folded_roots.len() != boundaries.len()
        || proof.body.folded_openings.len() != boundaries.len()
    {
        return Err(BatchVerifyErrorV09::InvalidProof);
    }

    let zs = derive_zs_batch_v09(params, commitment, &proof.body.folded_roots)
        .ok_or(BatchVerifyErrorV09::InvalidProof)?;

    let leaves0 = 1usize << (params.n + params.k - 1);
    let final_state = final_state_batch_v09(
        params,
        commitment,
        &proof.body.folded_roots,
        &proof.body.evals,
    )
    .ok_or(BatchVerifyErrorV09::InvalidProof)?;

    let gs = crate::transcript_v09::grind_seed_v09(&final_state, params.hash_kind);
    let nonce = match (params.g, proof.body.grind_nonce) {
        (0, None) => None,
        (0, Some(_)) => return Err(BatchVerifyErrorV09::InvalidProof),
        (_, Some(x))
            if crate::transcript_v09::valid_grind_nonce_v09(&gs, x, params.g, params.hash_kind) =>
        {
            Some(x)
        }
        _ => return Err(BatchVerifyErrorV09::InvalidProof),
    };

    let q0s = crate::transcript_v09::derive_queries_v09(
        &final_state,
        nonce,
        params.s,
        leaves0,
        params.hash_kind,
    );
    let keys = collect_gate_keys(params.n, &q0s, params.commit_every);
    prof.transcript = tr.elapsed();

    let gd = Instant::now();
    let (gates, p, i, b) = derive_sparse_gates(params.gate_seed, params.setup_counter, &keys);
    prof.gate_derivation = gd.elapsed();
    prof.gate_prf = p;
    prof.gate_batch_inverse = i;
    prof.gate_build = b;

    let ft = Instant::now();
    let ls = derive_lambdas(params.n, &keys, &gates, &zs);
    prof.folding += ft.elapsed();

    let d0 = params.commit_every.min(params.n);
    let ix0 = source_pair_indices(&q0s, 0, d0);

    let mt = Instant::now();
    let pairs0 = verify_base_opening(
        commitment,
        leaves0,
        &ix0,
        &proof.body.opening0,
        params.t,
        params.hash_kind,
    )
    .ok_or(BatchVerifyErrorV09::InvalidProof)?;
    prof.merkle += mt.elapsed();

    let ft = Instant::now();
    let mut known = known_first(params.n, d0, &q0s, &ix0, &pairs0, &keys, &ls)
        .ok_or(BatchVerifyErrorV09::InvalidProof)?;
    prof.folding += ft.elapsed();

    let mut a = d0;
    for (j, &bound) in boundaries.iter().enumerate() {
        if bound != a {
            return Err(BatchVerifyErrorV09::InvalidProof);
        }

        let d = params.commit_every.min(params.n - bound);
        let ix = source_pair_indices(&q0s, bound, d);
        let leaves = leaves0 >> bound;

        let mt = Instant::now();
        let pairs = verify_ext_compact(
            &proof.body.folded_roots[j],
            leaves,
            &ix,
            &known,
            &proof.body.folded_openings[j],
            params.t,
            params.hash_kind,
        )
        .ok_or(BatchVerifyErrorV09::InvalidProof)?;
        prof.merkle += mt.elapsed();

        let ft = Instant::now();
        known = known_ext(params.n, bound, d, &q0s, &ix, &pairs, &keys, &ls)
            .ok_or(BatchVerifyErrorV09::InvalidProof)?;
        prof.folding += ft.elapsed();

        a = bound + d;
    }

    if a != params.n || !(0..params.t).all(|c| known[c].values().all(|v| *v == proof.body.evals[c]))
    {
        return Err(BatchVerifyErrorV09::InvalidProof);
    }

    let accounted = prof.transcript + prof.gate_derivation + prof.merkle + prof.folding;
    prof.other = total
        .elapsed()
        .checked_sub(accounted)
        .unwrap_or(Duration::ZERO);

    Ok(prof)
}

pub fn prove_and_verify_batch_v09(
    coeff_batches: &[Vec<F128>],
    family: &GateFamily,
    params: &crate::transcript_v09::ParamsV09,
) -> Result<BatchTimingsV09, BatchVerifyErrorV09> {
    params
        .validate()
        .map_err(BatchVerifyErrorV09::InvalidParams)?;

    if coeff_batches.is_empty()
        || coeff_batches.len() != params.t
        || family.n != params.n
        || family.k != params.k
    {
        return Err(BatchVerifyErrorV09::InvalidParams(
            "batch params/family mismatch".into(),
        ));
    }

    let bt = coeff_batches.len();
    let coeff_len = 1usize << family.n;
    if !coeff_batches.iter().all(|c| c.len() == coeff_len) {
        return Err(BatchVerifyErrorV09::InvalidParams(
            "coefficient length mismatch".into(),
        ));
    }

    let stream = bt >= 32;
    let te = Instant::now();
    let mut word0s = coeff_batches
        .iter()
        .map(|c| encode(c, family))
        .collect::<Vec<_>>();
    let mut encode_t = te.elapsed();

    let tc = Instant::now();
    let tree0 = BatchMerkleTree::from_base(&word0s, params.hash_kind);
    let commitment = tree0.root();
    let commit0 = tc.elapsed();

    let header = params
        .header()
        .map_err(BatchVerifyErrorV09::InvalidParams)?;
    let boundaries = committed_boundaries(family.n, params.commit_every);
    let mut roots = Vec::with_capacity(boundaries.len());
    let mut committed_words = Vec::<Vec<Vec<F256>>>::with_capacity(boundaries.len());
    let mut committed_trees = Vec::<BatchMerkleTree>::with_capacity(boundaries.len());
    let mut state = crate::transcript_v09::initial_state_v09(&header, &commitment);

    let mut fold_total = Duration::ZERO;
    let mut commit_folds = Duration::ZERO;
    let mut current = Vec::<Vec<F256>>::new();
    let mut final_words = Vec::<Vec<F256>>::new();

    for (r, level) in family.levels.iter().rev().enumerate() {
        let z =
            crate::transcript_v09::challenge_field_v09(&state, b"fold", r as u64, params.hash_kind);

        let tf = Instant::now();
        if r == 0 {
            if stream {
                word0s.clear();
                word0s.shrink_to_fit();
                let re = Instant::now();
                current = coeff_batches
                    .iter()
                    .map(|c| {
                        let w = encode(c, family);
                        fold_first_level(&w, &level.gates, z)
                    })
                    .collect();
                encode_t += re.elapsed();
            } else {
                current = word0s
                    .iter()
                    .map(|w| fold_first_level(w, &level.gates, z))
                    .collect();
            }
        } else {
            for c in 0..current.len() {
                current[c] = fold_ext_level(&current[c], &level.gates, z);
            }
        }
        fold_total += tf.elapsed();

        let b = r + 1;
        if b < family.n && b % params.commit_every == 0 {
            let tc = Instant::now();
            let tree = BatchMerkleTree::from_ext(&current, params.hash_kind);
            let root = tree.root();
            commit_folds += tc.elapsed();

            roots.push(root);
            state.extend_from_slice(&root);
            committed_words.push(current.clone());
            committed_trees.push(tree);
        }

        if b == family.n {
            final_words = current.clone();
        }
    }

    let evals = final_words.iter().map(|w| w[0]).collect::<Vec<_>>();
    debug_assert!(final_words.iter().all(|w| w.iter().all(|x| *x == w[0])));

    let mut final_state = state.clone();
    crate::transcript_v09::append_batch_last_v09(&mut final_state, &evals);
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

    let to = Instant::now();
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

    if stream {
        let re = Instant::now();
        word0s = coeff_batches.iter().map(|c| encode(c, family)).collect();
        encode_t += re.elapsed();
    }

    let opening0 = tree0.open_base(&word0s, &ix0);
    let mut fops = Vec::with_capacity(boundaries.len());
    for (j, &b) in boundaries.iter().enumerate() {
        let d = params.commit_every.min(family.n - b);
        let ix = source_pair_indices(&q0s, b, d);
        let kp = target_positions(&q0s, b);
        fops.push(committed_trees[j].open_ext_compact(&committed_words[j], &ix, &kp));
    }
    let query_open = to.elapsed();

    let body = BatchProofV12 {
        folded_roots: roots,
        evals,
        grind_nonce: nonce,
        opening0,
        folded_openings: fops,
    };

    let proof = BatchProofV09 {
        proof_format_version: crate::transcript_v09::PROOF_FORMAT_VERSION_V09,
        header: header.serialize(),
        body,
    };

    let verify = verify_batch_v09(params, &commitment, &proof)?;
    let challenges = derive_zs_batch_v09(params, &commitment, &proof.body.folded_roots)
        .ok_or(BatchVerifyErrorV09::InvalidProof)?;

    let nword = 1usize << (family.n + family.k);
    let base_bytes = bt * nword * 16;
    let ext_bytes = bt * (nword / 2) * 32;
    let tree_bytes = (nword / 2) * 2 * 32;
    let committed_est = if params.commit_every >= usize::BITS as usize {
        0
    } else {
        ext_bytes / ((1usize << params.commit_every).saturating_sub(1).max(1))
    };

    let peak = if stream {
        base_bytes.max(ext_bytes) + tree_bytes + committed_est
    } else {
        base_bytes + ext_bytes + tree_bytes + committed_est
    };

    Ok(BatchTimingsV09 {
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
        peak_memory_estimate_bytes: peak,
    })
}

#[cfg(test)]
mod v09_batch_transcript_tests {
    use super::*;
    use crate::{security::soundness_bits_from, transcript_v09::ParamsV09};

    fn required_s(n: usize, k: usize, i0: usize, g: u32, target: u32) -> usize {
        soundness_bits_from(n, k, 128.0, 256.0, g as f64, (target - 128) as f64, i0).s
    }

    fn params_for(n: usize, k: usize, t: usize, seed: u64, setup_counter: u64) -> ParamsV09 {
        ParamsV09 {
            n,
            k,
            i0: 3,
            s: required_s(n, k, 3, 0, 192),
            g: 0,
            t,
            commit_every: 3.min(n),
            gate_seed: seed,
            setup_counter,
            hash_kind: HashKind::Blake3,
            target_bits: 192,
        }
    }

    fn coeff_batches(t: usize, n: usize) -> Vec<Vec<F128>> {
        (0..t)
            .map(|c| {
                (0..(1usize << n))
                    .map(|i| F128(1 + (c as u128) * 100_000 + i as u128))
                    .collect()
            })
            .collect()
    }

    fn make_batch(n: usize, t: usize) -> (ParamsV09, BatchTimingsV09) {
        let seed = 0xB47C0u64 + n as u64 + t as u64;
        let k = 2usize;
        let checked = GateFamily::from_seed_checked_i0_3(n, k, seed);
        let p = params_for(n, k, t, seed, checked.counter);
        let cs = coeff_batches(t, n);
        let run = prove_and_verify_batch_v09(&cs, &checked.family, &p).unwrap();
        (p, run)
    }

    #[test]
    fn v09_round_trip_batch_n8_n10_n12() {
        for n in [8usize, 10, 12] {
            let (_p, run) = make_batch(n, 4);
            assert!(run.verified, "n={n}");
        }
    }

    #[test]
    fn v09_batch_last_layer_binds_queries() {
        let (p, run) = make_batch(8, 4);
        let mut bad = run.proof.clone();
        bad.body.evals[1] += F256::ONE;
        assert!(verify_batch_v09(&p, &run.commitment, &bad).is_err());
    }

    #[test]
    fn v09_batch_header_copy_corruption_rejected() {
        let (p, run) = make_batch(8, 4);
        let mut bad = run.proof.clone();
        let i = bad.header.len() / 2;
        bad.header[i] ^= 1;
        assert!(matches!(
            verify_batch_v09(&p, &run.commitment, &bad),
            Err(BatchVerifyErrorV09::HeaderMismatch)
        ));
    }
}

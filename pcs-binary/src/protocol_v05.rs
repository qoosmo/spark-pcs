use crate::{
    encode::{derive_raw_gate_with_counter, encode, GateFamily},
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
pub struct SparkProofV05 {
    pub folded_roots: Vec<Hash>,
    pub eval: F256,
    pub grind_nonce: Option<u64>,
    pub opening0: MultiOpening<F128>,
    pub folded_openings: Vec<CompactOpening<F256>>,
}
impl SparkProofV05 {
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
pub struct TimingsV05 {
    pub encode: Duration,
    pub commit0: Duration,
    pub fold_total: Duration,
    pub commit_folds: Duration,
    pub query_open: Duration,
    pub grind: Duration,
    pub gate_derive_verify: Duration,
    pub verify_checks: Duration,
    pub commitment: Hash,
    pub proof: SparkProofV05,
    pub verified: bool,
}
impl TimingsV05 {
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
        &[b"SPARK-FS-v0.5", label, &counter.to_le_bytes(), state],
    ))
}
fn challenge_index(state: &[u8], counter: u64, modulus: usize, kind: HashKind) -> usize {
    let d = hash_parts(kind, &[b"SPARK-QUERY-v0.5", &counter.to_le_bytes(), state]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    (u64::from_le_bytes(b) as usize) % modulus
}
fn derive_zs(commitment: &Hash, roots: &[Hash], n: usize, kind: HashKind) -> Vec<F256> {
    let mut st = Vec::new();
    st.extend_from_slice(commitment);
    let mut z = Vec::with_capacity(n);
    for r in 0..n {
        z.push(challenge_field(&st, b"fold", r as u64, kind));
        if r + 1 < n {
            st.extend_from_slice(&roots[r]);
        }
    }
    z
}
fn query_transcript(commitment: &Hash, roots: &[Hash], eval: F256) -> Vec<u8> {
    let mut st = Vec::with_capacity(32 * (roots.len() + 2));
    st.extend_from_slice(commitment);
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

fn grind_seed(commitment: &Hash, roots: &[Hash], eval: F256, kind: HashKind) -> Hash {
    let st = query_transcript(commitment, roots, eval);
    hash_parts(kind, &[b"SPARK-GRIND-SEED-v0.6", &st])
}

fn valid_grind_nonce(seed: &Hash, nonce: u64, bits: u32, kind: HashKind) -> bool {
    if bits == 0 {
        return nonce == 0;
    }
    let d = hash_parts(kind, &[b"SPARK-GRIND-v0.6", seed, &nonce.to_le_bytes()]);
    leading_zero_bits(&d) >= bits
}

fn find_grind_nonce(seed: &Hash, bits: u32, kind: HashKind) -> u64 {
    assert!(bits <= 32, "benchmark grinding is limited to 32 bits");
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
    grind_nonce: Option<u64>,
    s: usize,
    leaves: usize,
    kind: HashKind,
) -> Vec<usize> {
    let mut st = query_transcript(commitment, roots, eval);
    if let Some(nonce) = grind_nonce {
        st.extend_from_slice(b"SPARK-GRIND-NONCE-v0.6");
        st.extend_from_slice(&nonce.to_le_bytes());
    }
    (0..s)
        .map(|i| challenge_index(&st, i as u64, leaves, kind))
        .collect()
}
fn uniq(q: &[usize], r: usize) -> Vec<usize> {
    let mut v = q.iter().map(|x| x >> r).collect::<Vec<_>>();
    v.sort_unstable();
    v.dedup();
    v
}
fn val128(ix: &[usize], op: &MultiOpening<F128>, q: usize) -> Option<[F128; 2]> {
    ix.binary_search(&q).ok().map(|p| op.values[p])
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

/// Derive only the gates touched by the verifier's query chains, then batch-invert their denominators.
fn derive_verifier_gates(
    seed: u64,
    setup_counter: u64,
    n: usize,
    q0s: &[usize],
) -> HashMap<(usize, usize), Gate> {
    let mut keys = Vec::new();
    for &q in q0s {
        for r in 0..n {
            keys.push((n - 1 - r, q >> r));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    let raw = keys
        .iter()
        .map(|&(l, i)| derive_raw_gate_with_counter(seed, setup_counter, l, i))
        .collect::<Vec<_>>();
    let den = raw.iter().map(|(a, b)| *a + *b).collect::<Vec<_>>();
    let inv = batch_inverse(&den);
    keys.into_iter()
        .zip(raw)
        .zip(inv)
        .map(|(((l, i), (t0, t1)), iv)| ((l, i), Gate::new(t0, t1, iv)))
        .collect()
}

pub fn verify_v05(
    seed: u64,
    setup_counter: u64,
    n: usize,
    k: usize,
    commitment: &Hash,
    proof: &SparkProofV05,
    s: usize,
    grind_bits: u32,
    kind: HashKind,
) -> (bool, Duration, Duration) {
    if n == 0
        || proof.folded_roots.len() + 1 != n
        || proof.folded_openings.len() + 1 != n
        || s == 0
        || grind_bits > 32
    {
        return (false, Duration::ZERO, Duration::ZERO);
    }
    let zs = derive_zs(commitment, &proof.folded_roots, n, kind);
    let initial_leaves = 1usize << (n + k - 1);
    let grind_seed = grind_seed(commitment, &proof.folded_roots, proof.eval, kind);
    let grind_nonce = match (grind_bits, proof.grind_nonce) {
        (0, None) => None,
        (0, Some(_)) => return (false, Duration::ZERO, Duration::ZERO),
        (_, Some(nonce)) if valid_grind_nonce(&grind_seed, nonce, grind_bits, kind) => Some(nonce),
        _ => return (false, Duration::ZERO, Duration::ZERO),
    };
    let q0s = derive_queries(
        commitment,
        &proof.folded_roots,
        proof.eval,
        grind_nonce,
        s,
        initial_leaves,
        kind,
    );
    let t = Instant::now();
    let gates = derive_verifier_gates(seed, setup_counter, n, &q0s);
    let gate_t = t.elapsed();
    let t = Instant::now();
    let mut indices = Vec::with_capacity(n);
    for r in 0..n {
        indices.push(uniq(&q0s, r));
    }
    if !MerkleTreeV05::<F128>::verify_pairs(
        commitment,
        initial_leaves,
        &indices[0],
        &proof.opening0,
        kind,
    ) {
        return (false, gate_t, t.elapsed());
    }

    // Fold every distinct queried E0 pair once. These are authenticated values
    // of E1, keyed by their absolute position, so E1 need not serialize them.
    let mut known: HashMap<usize, F256> = HashMap::with_capacity(indices[0].len());
    for (p, pair) in indices[0]
        .iter()
        .copied()
        .zip(proof.opening0.values.iter().copied())
    {
        let g = match gates.get(&(n - 1, p)) {
            Some(x) => *x,
            None => return (false, gate_t, t.elapsed()),
        };
        known.insert(p, fold_first(g, pair[0], pair[1], zs[0]));
    }

    // Verify each folded layer using the child values reconstructed above,
    // then fold its complete queried pairs to reconstruct the next layer.
    for r in 1..n {
        let leaves = initial_leaves >> r;
        let pairs = match MerkleTreeV05::<F256>::verify_pairs_compact(
            &proof.folded_roots[r - 1],
            leaves,
            &indices[r],
            &known,
            &proof.folded_openings[r - 1],
            kind,
        ) {
            Some(v) => v,
            None => return (false, gate_t, t.elapsed()),
        };

        let mut next_known: HashMap<usize, F256> = HashMap::with_capacity(indices[r].len());
        for (p, pair) in indices[r].iter().copied().zip(pairs.iter().copied()) {
            let g = match gates.get(&(n - 1 - r, p)) {
                Some(x) => *x,
                None => return (false, gate_t, t.elapsed()),
            };
            let folded = fold_ext(g, pair[0], pair[1], zs[r]);
            if r + 1 < n {
                next_known.insert(p, folded);
            } else if folded != proof.eval {
                return (false, gate_t, t.elapsed());
            }
        }
        known = next_known;
    }
    (true, gate_t, t.elapsed())
}

pub fn prove_and_verify_v05(
    coeffs: &[F128],
    family: &GateFamily,
    seed: u64,
    setup_counter: u64,
    s: usize,
    grind_bits: u32,
    kind: HashKind,
) -> TimingsV05 {
    let t = Instant::now();
    let word0 = encode(coeffs, family);
    let encode_t = t.elapsed();
    let t = Instant::now();
    let tree0 = MerkleTreeV05::<F128>::from_pairs(&word0, kind);
    let commitment = tree0.root();
    let commit0 = t.elapsed();
    let mut folded_words: Vec<Vec<F256>> = Vec::with_capacity(family.n.saturating_sub(1));
    let mut folded_trees = Vec::with_capacity(family.n.saturating_sub(1));
    let mut roots = Vec::with_capacity(family.n.saturating_sub(1));
    let mut state = Vec::new();
    state.extend_from_slice(&commitment);
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
        if r + 1 < family.n {
            let t = Instant::now();
            let tree = MerkleTreeV05::<F256>::from_pairs(&next, kind);
            let root = tree.root();
            commit_folds += t.elapsed();
            roots.push(root);
            state.extend_from_slice(&root);
            folded_words.push(next.clone());
            folded_trees.push(tree);
            current_ext = Some(next);
        } else {
            final_word = next;
        }
    }
    let eval = final_word[0];
    debug_assert!(final_word.iter().all(|x| *x == eval));
    let grind_seed = grind_seed(&commitment, &roots, eval, kind);
    let t = Instant::now();
    let grind_nonce = if grind_bits == 0 {
        None
    } else {
        Some(find_grind_nonce(&grind_seed, grind_bits, kind))
    };
    let grind = t.elapsed();

    let t = Instant::now();
    let leaves = 1usize << (family.n + family.k - 1);
    let q0s = derive_queries(&commitment, &roots, eval, grind_nonce, s, leaves, kind);
    let mut indices = Vec::with_capacity(family.n);
    for r in 0..family.n {
        indices.push(uniq(&q0s, r));
    }
    let opening0 = tree0.open_pairs(&word0, &indices[0]);
    let mut fops = Vec::with_capacity(family.n - 1);
    for r in 1..family.n {
        // Each position in indices[r-1] is exactly one child value of a
        // queried pair at layer r, and is recomputable from the previous layer.
        fops.push(folded_trees[r - 1].open_pairs_compact(
            &folded_words[r - 1],
            &indices[r],
            &indices[r - 1],
        ));
    }
    let query_open = t.elapsed();
    let proof = SparkProofV05 {
        folded_roots: roots,
        eval,
        grind_nonce,
        opening0,
        folded_openings: fops,
    };
    let (verified, gate_t, check_t) = verify_v05(
        seed,
        setup_counter,
        family.n,
        family.k,
        &commitment,
        &proof,
        s,
        grind_bits,
        kind,
    );
    TimingsV05 {
        encode: encode_t,
        commit0,
        fold_total,
        commit_folds,
        query_open,
        grind,
        gate_derive_verify: gate_t,
        verify_checks: check_t,
        commitment,
        proof,
        verified,
    }
}

#[cfg(test)]
mod grind_tests {
    use super::*;

    #[test]
    fn real_grinding_finds_and_checks_nonce() {
        let seed = [7u8; 32];
        let nonce = find_grind_nonce(&seed, 8, HashKind::Blake3);
        assert!(valid_grind_nonce(&seed, nonce, 8, HashKind::Blake3));
        let mut bad = nonce.wrapping_add(1);
        while valid_grind_nonce(&seed, bad, 8, HashKind::Blake3) {
            bad = bad.wrapping_add(1);
        }
        assert!(!valid_grind_nonce(&seed, bad, 8, HashKind::Blake3));
    }
}

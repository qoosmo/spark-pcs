// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{extfield::F256, field::F128};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    Blake3,
    Sha256,
}
impl HashKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "blake3" => Self::Blake3,
            "sha256" | "sha-256" => Self::Sha256,
            _ => panic!("hash must be blake3 or sha256"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "BLAKE3",
            Self::Sha256 => "SHA-256",
        }
    }
}

pub trait MerkleElem: Copy + Send + Sync + Eq + std::fmt::Debug + 'static {
    const SIZE: usize;
    fn encode(self, out: &mut [u8; 32]);
}
impl MerkleElem for F128 {
    const SIZE: usize = 16;
    fn encode(self, out: &mut [u8; 32]) {
        out[..16].copy_from_slice(&self.to_le_bytes());
    }
}
impl MerkleElem for F256 {
    const SIZE: usize = 32;
    fn encode(self, out: &mut [u8; 32]) {
        out.copy_from_slice(&self.to_le_bytes());
    }
}

#[inline]
fn digest(kind: HashKind, parts: &[&[u8]]) -> Hash {
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
fn h_leaf<T: MerkleElem>(kind: HashKind, a: T, b: T) -> Hash {
    #[cfg(feature = "brief18t_instrument")]
    crate::instrument::inc_hash();
    let mut ab = [0u8; 32];
    let mut bb = [0u8; 32];
    a.encode(&mut ab);
    b.encode(&mut bb);
    match kind {
        HashKind::Blake3 => {
            // Hash exactly the same byte string as the incremental version, but
            // with one BLAKE3 call. This avoids Hasher construction + 3 updates
            // for every verifier leaf.
            const DOMAIN: &[u8] = b"SPARK-BINARY-LEAF-v0.5";
            let mut buf = [0u8; 96];
            let mut off = 0usize;
            buf[off..off + DOMAIN.len()].copy_from_slice(DOMAIN);
            off += DOMAIN.len();
            buf[off..off + T::SIZE].copy_from_slice(&ab[..T::SIZE]);
            off += T::SIZE;
            buf[off..off + T::SIZE].copy_from_slice(&bb[..T::SIZE]);
            off += T::SIZE;
            *blake3::hash(&buf[..off]).as_bytes()
        }
        HashKind::Sha256 => digest(
            kind,
            &[b"SPARK-BINARY-LEAF-v0.5", &ab[..T::SIZE], &bb[..T::SIZE]],
        ),
    }
}
/// Block leaf: one hash over a whole aligned block of `2^g` pairs (`g >= 1`).
/// Domain-separated from pair leaves, so the two layouts can never collide.
#[inline]
fn h_block<T: MerkleElem>(kind: HashKind, blk: &[T]) -> Hash {
    #[cfg(feature = "brief18t_instrument")]
    crate::instrument::inc_hash();
    const DOMAIN: &[u8] = b"SPARK-BINARY-BLOCK-v1";
    let mut tmp = [0u8; 32];
    match kind {
        HashKind::Blake3 => {
            let mut h = blake3::Hasher::new();
            h.update(DOMAIN);
            for &x in blk {
                x.encode(&mut tmp);
                h.update(&tmp[..T::SIZE]);
            }
            *h.finalize().as_bytes()
        }
        HashKind::Sha256 => {
            let mut h = Sha256::new();
            h.update(DOMAIN);
            for &x in blk {
                x.encode(&mut tmp);
                h.update(&tmp[..T::SIZE]);
            }
            h.finalize().into()
        }
    }
}

/// Hash of the leaf covering pairs `[i*2^g, (i+1)*2^g)`, given those pairs.
#[inline]
fn h_leaf_group<T: MerkleElem>(kind: HashKind, pairs: &[[T; 2]], g: u32) -> Hash {
    if g == 0 {
        h_leaf(kind, pairs[0][0], pairs[0][1])
    } else {
        let flat: Vec<T> = pairs.iter().flat_map(|p| [p[0], p[1]]).collect();
        h_block(kind, &flat)
    }
}

/// Check that sorted pair `indices` consist of complete aligned groups of `2^g` pairs,
/// and return the (sorted, deduplicated) group indices.
fn group_indices(indices: &[usize], g: u32) -> Option<Vec<usize>> {
    let w = 1usize << g;
    if indices.len() % w != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(indices.len() / w);
    for chunk in indices.chunks(w) {
        let base = chunk[0];
        if base % w != 0 {
            return None;
        }
        for (j, &i) in chunk.iter().enumerate() {
            if i != base + j {
                return None;
            }
        }
        out.push(base >> g);
    }
    Some(out)
}

#[inline]
fn h_node(kind: HashKind, l: &Hash, r: &Hash) -> Hash {
    #[cfg(feature = "brief18t_instrument")]
    crate::instrument::inc_hash();
    match kind {
        HashKind::Blake3 => {
            // Same transcript bytes, one BLAKE3 call instead of 3 updates.
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
        HashKind::Sha256 => digest(kind, &[b"SPARK-BINARY-NODE-v0.5", l, r]),
    }
}

/// Verify a Merkle multiproof frontier using the fact that `indices` are
/// strictly increasing. The old verifier rebuilt a HashMap and sorted parent
/// keys at every tree level. Here every level is a single linear scan.
fn verify_frontier_sorted(
    root: &Hash,
    leaf_count: usize,
    indices: &[usize],
    leaf_hashes: Vec<Hash>,
    auth: &[Hash],
    #[allow(dead_code)] kind: HashKind,
) -> bool {
    if indices.len() != leaf_hashes.len() {
        return false;
    }
    let mut cur = indices.iter().copied().zip(leaf_hashes).collect::<Vec<_>>();
    let mut next = Vec::<(usize, Hash)>::with_capacity(cur.len().div_ceil(2));
    let mut ap = 0usize;
    let depth = leaf_count.trailing_zeros() as usize;

    for _ in 0..depth {
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
                    r = sib;
                } else {
                    l = sib;
                    r = h;
                }
                i += 1;
            }
            next.push((idx >> 1, h_node(kind, &l, &r)));
        }
        std::mem::swap(&mut cur, &mut next);
    }

    ap == auth.len() && cur.len() == 1 && cur[0].0 == 0 && cur[0].1 == *root
}

#[derive(Clone, Debug)]
pub struct MultiOpening<T: MerkleElem> {
    pub values: Vec<[T; 2]>,
    pub auth: Vec<Hash>,
}
impl<T: MerkleElem> MultiOpening<T> {
    pub fn serialized_size_bytes(&self) -> usize {
        self.values.len() * 2 * T::SIZE + self.auth.len() * 32
    }
}

#[derive(Clone, Debug)]
pub struct CompactOpening<T: MerkleElem> {
    /// Only values that are not derivable from the previous queried layer.
    /// Order is deterministic: leaf order, then left/right position.
    pub values: Vec<T>,
    pub auth: Vec<Hash>,
}
impl<T: MerkleElem> CompactOpening<T> {
    pub fn serialized_size_bytes(&self) -> usize {
        self.values.len() * T::SIZE + self.auth.len() * 32
    }
}

#[derive(Clone, Debug)]
pub struct MerkleTreeV05<T: MerkleElem> {
    levels: Vec<Vec<Hash>>,
    #[allow(dead_code)]
    kind: HashKind,
    /// log2 of the number of pairs per leaf (0 = one pair per leaf, the v0.5..v0.10 layout).
    group_log: u32,
    _m: std::marker::PhantomData<T>,
}
impl<T: MerkleElem> MerkleTreeV05<T> {
    pub fn from_pairs(word: &[T], kind: HashKind) -> Self {
        Self::from_pairs_grouped(word, kind, 0)
    }
    /// Build the tree with one leaf per aligned block of `2^group_log` pairs.
    pub fn from_pairs_grouped(word: &[T], kind: HashKind, group_log: u32) -> Self {
        let w = 2usize << group_log;
        assert!(word.len().is_power_of_two() && word.len() >= w);
        let leaves = if group_log == 0 {
            word.par_chunks_exact(2)
                .map(|w| h_leaf(kind, w[0], w[1]))
                .collect::<Vec<_>>()
        } else {
            word.par_chunks_exact(w)
                .map(|blk| h_block(kind, blk))
                .collect::<Vec<_>>()
        };
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
        Self {
            levels,
            kind,
            group_log,
            _m: std::marker::PhantomData,
        }
    }
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }
    pub fn open_pairs(&self, word: &[T], indices: &[usize]) -> MultiOpening<T> {
        assert_eq!((self.levels[0].len() * 2) << self.group_log, word.len());
        assert!(!indices.is_empty());
        let values = indices
            .iter()
            .map(|&i| [word[2 * i], word[2 * i + 1]])
            .collect();
        let mut auth = Vec::new();
        let mut cur = group_indices(indices, self.group_log)
            .expect("queried pairs must form complete aligned leaf groups");
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
        MultiOpening { values, auth }
    }
    /// Open queried pairs while omitting positions already known to the verifier.
    /// `known_positions` are absolute positions in `word`, sorted and deduplicated.
    pub fn open_pairs_compact(
        &self,
        word: &[T],
        indices: &[usize],
        known_positions: &[usize],
    ) -> CompactOpening<T> {
        assert_eq!((self.levels[0].len() * 2) << self.group_log, word.len());
        assert!(!indices.is_empty());
        debug_assert!(known_positions.windows(2).all(|w| w[0] < w[1]));

        let mut values = Vec::new();
        for &i in indices {
            for pos in [2 * i, 2 * i + 1] {
                if known_positions.binary_search(&pos).is_err() {
                    values.push(word[pos]);
                }
            }
        }

        let mut auth = Vec::new();
        let mut cur = group_indices(indices, self.group_log)
            .expect("queried pairs must form complete aligned leaf groups");
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
        CompactOpening { values, auth }
    }

    /// Verify a compact opening using values reconstructed from the previous layer.
    /// Returns the complete queried pairs on success so the caller can fold them
    /// and use the results as known positions in the next layer.
    pub fn verify_pairs_compact(
        root: &Hash,
        leaf_count: usize,
        indices: &[usize],
        known: &HashMap<usize, T>,
        op: &CompactOpening<T>,
        kind: HashKind,
    ) -> Option<Vec<[T; 2]>> {
        Self::verify_pairs_compact_grouped(root, leaf_count, indices, known, op, kind, 0)
    }

    /// `leaf_count` is the number of *pairs*; the tree has `leaf_count >> g` leaves.
    pub fn verify_pairs_compact_grouped(
        root: &Hash,
        leaf_count: usize,
        indices: &[usize],
        known: &HashMap<usize, T>,
        op: &CompactOpening<T>,
        kind: HashKind,
        g: u32,
    ) -> Option<Vec<[T; 2]>> {
        if !leaf_count.is_power_of_two() || indices.is_empty() || (leaf_count >> g) == 0 {
            return None;
        }
        if *indices.last()? >= leaf_count || !indices.windows(2).all(|w| w[0] < w[1]) {
            return None;
        }

        let mut vp = 0usize;
        let mut pairs = Vec::with_capacity(indices.len());
        let mut leaf_hashes: Vec<Hash> = Vec::with_capacity(indices.len());
        for &i in indices {
            let mut next_value = |pos: usize| -> Option<T> {
                if let Some(v) = known.get(&pos) {
                    Some(*v)
                } else if vp < op.values.len() {
                    let v = op.values[vp];
                    vp += 1;
                    Some(v)
                } else {
                    None
                }
            };
            let a = next_value(2 * i)?;
            let b = next_value(2 * i + 1)?;
            pairs.push([a, b]);
            if g == 0 {
                leaf_hashes.push(h_leaf(kind, a, b));
            }
        }
        if vp != op.values.len() {
            return None;
        }
        let groups = group_indices(indices, g)?;
        if g > 0 {
            let w = 1usize << g;
            leaf_hashes = pairs.chunks(w).map(|c| h_leaf_group(kind, c, g)).collect();
        }

        if verify_frontier_sorted(root, leaf_count >> g, &groups, leaf_hashes, &op.auth, kind) {
            Some(pairs)
        } else {
            None
        }
    }

    pub fn verify_pairs(
        root: &Hash,
        leaf_count: usize,
        indices: &[usize],
        op: &MultiOpening<T>,
        kind: HashKind,
    ) -> bool {
        Self::verify_pairs_grouped(root, leaf_count, indices, op, kind, 0)
    }

    /// `leaf_count` is the number of *pairs*; the tree has `leaf_count >> g` leaves.
    pub fn verify_pairs_grouped(
        root: &Hash,
        leaf_count: usize,
        indices: &[usize],
        op: &MultiOpening<T>,
        kind: HashKind,
        g: u32,
    ) -> bool {
        if !leaf_count.is_power_of_two() || indices.is_empty() || indices.len() != op.values.len() {
            return false;
        }
        if (leaf_count >> g) == 0 {
            return false;
        }
        if *indices.last().unwrap() >= leaf_count || !indices.windows(2).all(|w| w[0] < w[1]) {
            return false;
        }
        let groups = match group_indices(indices, g) {
            Some(x) => x,
            None => return false,
        };
        let w = 1usize << g;
        let leaf_hashes = op
            .values
            .chunks(w)
            .map(|c| h_leaf_group(kind, c, g))
            .collect::<Vec<_>>();
        verify_frontier_sorted(root, leaf_count >> g, &groups, leaf_hashes, &op.auth, kind)
    }
}

#[cfg(test)]
mod compact_auth_tests {
    use super::*;

    #[test]
    fn blake3_one_shot_hashing_matches_incremental_transcript() {
        let a = F256::from_base(F128(123));
        let b = F256::from_base(F128(456));
        let mut ab = [0u8; 32];
        let mut bb = [0u8; 32];
        a.encode(&mut ab);
        b.encode(&mut bb);
        let old_leaf = digest(HashKind::Blake3, &[b"SPARK-BINARY-LEAF-v0.5", &ab, &bb]);
        assert_eq!(h_leaf(HashKind::Blake3, a, b), old_leaf);

        let l = [7u8; 32];
        let r = [9u8; 32];
        let old_node = digest(HashKind::Blake3, &[b"SPARK-BINARY-NODE-v0.5", &l, &r]);
        assert_eq!(h_node(HashKind::Blake3, &l, &r), old_node);
    }

    #[test]
    fn compact_opening_rejects_wrong_derived_value_against_committed_leaf() {
        // The committed next-layer table contains position 2 = 1, while the
        // verifier's derived fold says position 2 = 0.  Position 2 is omitted
        // from the proof and reconstructed from `known`; the Merkle check must fail.
        let word = vec![
            F256::from_base(F128(10)),
            F256::from_base(F128(11)),
            F256::ONE,
            F256::from_base(F128(13)),
            F256::from_base(F128(14)),
            F256::from_base(F128(15)),
            F256::from_base(F128(16)),
            F256::from_base(F128(17)),
        ];
        let tree = MerkleTreeV05::<F256>::from_pairs(&word, HashKind::Blake3);
        let indices = vec![1usize];
        let known_positions = vec![2usize];
        let opening = tree.open_pairs_compact(&word, &indices, &known_positions);

        let mut known = HashMap::new();
        known.insert(2usize, F256::ZERO); // true derived fold, unlike committed word[2]

        assert!(MerkleTreeV05::<F256>::verify_pairs_compact(
            &tree.root(),
            word.len() / 2,
            &indices,
            &known,
            &opening,
            HashKind::Blake3,
        )
        .is_none());
    }
    fn sample_word(n: usize) -> Vec<F256> {
        (0..n)
            .map(|i| F256::from_base(F128((i as u128).wrapping_mul(0x9e3779b97f4a7c15) ^ 7)))
            .collect()
    }

    #[test]
    fn grouped_zero_is_bit_identical_to_pair_leaves() {
        let w = sample_word(64);
        let a = MerkleTreeV05::<F256>::from_pairs(&w, HashKind::Blake3);
        let b = MerkleTreeV05::<F256>::from_pairs_grouped(&w, HashKind::Blake3, 0);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn block_leaves_round_trip_and_tamper() {
        for g in 1u32..=3 {
            let w = sample_word(128);
            let pairs = w.len() / 2;
            let tree = MerkleTreeV05::<F256>::from_pairs_grouped(&w, HashKind::Blake3, g);
            let pair_root = MerkleTreeV05::<F256>::from_pairs(&w, HashKind::Blake3).root();
            assert_ne!(tree.root(), pair_root, "layouts must be domain-separated");
            let width = 1usize << g;
            // two complete groups
            let mut ix: Vec<usize> = (width..2 * width).chain(5 * width..6 * width).collect();
            ix.sort_unstable();
            let op = tree.open_pairs(&w, &ix);
            assert!(MerkleTreeV05::<F256>::verify_pairs_grouped(
                &tree.root(), pairs, &ix, &op, HashKind::Blake3, g
            ));
            // tamper a value
            let mut bad = op.clone();
            bad.values[1][0] = F256::from_base(F128(999));
            assert!(!MerkleTreeV05::<F256>::verify_pairs_grouped(
                &tree.root(), pairs, &ix, &bad, HashKind::Blake3, g
            ));
            // tamper an auth digest
            let mut bad = op.clone();
            bad.auth[0][0] ^= 1;
            assert!(!MerkleTreeV05::<F256>::verify_pairs_grouped(
                &tree.root(), pairs, &ix, &bad, HashKind::Blake3, g
            ));
            // an incomplete group is rejected
            let partial = &ix[1..];
            let op2 = MultiOpening { values: op.values[1..].to_vec(), auth: op.auth.clone() };
            assert!(!MerkleTreeV05::<F256>::verify_pairs_grouped(
                &tree.root(), pairs, partial, &op2, HashKind::Blake3, g
            ));
            // compact opening with known positions
            let known_pos: Vec<usize> = vec![2 * width, 2 * (5 * width) + 1];
            let cop = tree.open_pairs_compact(&w, &ix, &known_pos);
            let mut known = HashMap::new();
            for &pos in &known_pos {
                known.insert(pos, w[pos]);
            }
            let got = MerkleTreeV05::<F256>::verify_pairs_compact_grouped(
                &tree.root(), pairs, &ix, &known, &cop, HashKind::Blake3, g,
            )
            .expect("compact grouped opening verifies");
            assert_eq!(got.len(), ix.len());
            known.insert(known_pos[0], F256::from_base(F128(12345)));
            assert!(MerkleTreeV05::<F256>::verify_pairs_compact_grouped(
                &tree.root(), pairs, &ix, &known, &cop, HashKind::Blake3, g,
            )
            .is_none());
        }
    }
}

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
#[inline]
fn h_node(kind: HashKind, l: &Hash, r: &Hash) -> Hash {
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
    _m: std::marker::PhantomData<T>,
}
impl<T: MerkleElem> MerkleTreeV05<T> {
    pub fn from_pairs(word: &[T], kind: HashKind) -> Self {
        assert!(word.len().is_power_of_two() && word.len() >= 2);
        let leaves = word
            .par_chunks_exact(2)
            .map(|w| h_leaf(kind, w[0], w[1]))
            .collect::<Vec<_>>();
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
            _m: std::marker::PhantomData,
        }
    }
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }
    pub fn open_pairs(&self, word: &[T], indices: &[usize]) -> MultiOpening<T> {
        assert_eq!(self.levels[0].len() * 2, word.len());
        assert!(!indices.is_empty());
        let values = indices
            .iter()
            .map(|&i| [word[2 * i], word[2 * i + 1]])
            .collect();
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
        assert_eq!(self.levels[0].len() * 2, word.len());
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
        if !leaf_count.is_power_of_two() || indices.is_empty() {
            return None;
        }
        if *indices.last()? >= leaf_count || !indices.windows(2).all(|w| w[0] < w[1]) {
            return None;
        }

        let mut vp = 0usize;
        let mut pairs = Vec::with_capacity(indices.len());
        let mut leaf_hashes = Vec::with_capacity(indices.len());
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
            leaf_hashes.push(h_leaf(kind, a, b));
        }
        if vp != op.values.len() {
            return None;
        }

        if verify_frontier_sorted(root, leaf_count, indices, leaf_hashes, &op.auth, kind) {
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
        if !leaf_count.is_power_of_two() || indices.is_empty() || indices.len() != op.values.len() {
            return false;
        }
        if *indices.last().unwrap() >= leaf_count || !indices.windows(2).all(|w| w[0] < w[1]) {
            return false;
        }
        let leaf_hashes = op
            .values
            .iter()
            .map(|v| h_leaf(kind, v[0], v[1]))
            .collect::<Vec<_>>();
        verify_frontier_sorted(root, leaf_count, indices, leaf_hashes, &op.auth, kind)
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
}

// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::field::F128;
use rayon::prelude::*;
use std::collections::HashMap;

pub type Hash = [u8; 32];

#[inline]
fn h_leaf(a: F128, b: F128) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SPARK-BINARY-LEAF");
    hasher.update(&a.to_le_bytes());
    hasher.update(&b.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[inline]
fn h_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SPARK-BINARY-NODE");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug)]
pub struct MerkleOpening {
    pub values: [F128; 2],
    pub path: Vec<Hash>,
}

/// Canonical multiproof for a sorted, deduplicated list of pair-leaf indices.
/// Indices are Fiat-Shamir derived and therefore are not serialized in the proof.
#[derive(Clone, Debug)]
pub struct MerkleMultiOpening {
    pub values: Vec<[F128; 2]>,
    pub auth: Vec<Hash>,
}

impl MerkleMultiOpening {
    #[inline]
    pub fn serialized_size_bytes(&self) -> usize {
        self.values.len() * 32 + self.auth.len() * 32
    }
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    // levels[0] are pair-leaf hashes; last level contains one root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Parallel Merkle construction. Hashing dominated v0.3 prover time, so all
    /// leaf and internal-node levels are now built with Rayon.
    pub fn from_pairs(word: &[F128]) -> Self {
        assert!(word.len().is_power_of_two());
        assert!(word.len() >= 2);
        let leaves = word
            .par_chunks_exact(2)
            .map(|w| h_leaf(w[0], w[1]))
            .collect::<Vec<_>>();
        assert!(leaves.len().is_power_of_two());

        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .par_chunks_exact(2)
                .map(|p| h_node(&p[0], &p[1]))
                .collect::<Vec<_>>();
            levels.push(next);
        }
        Self { levels }
    }

    #[inline]
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    pub fn open_pair(&self, word: &[F128], pair_index: usize) -> MerkleOpening {
        assert_eq!(self.levels[0].len() * 2, word.len());
        assert!(pair_index < self.levels[0].len());
        let values = [word[2 * pair_index], word[2 * pair_index + 1]];
        let mut index = pair_index;
        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1]);
            index >>= 1;
        }
        MerkleOpening { values, path }
    }

    pub fn verify_pair(root: &Hash, pair_index: usize, opening: &MerkleOpening) -> bool {
        if opening.path.len() >= usize::BITS as usize {
            return false;
        }
        if pair_index >= (1usize << opening.path.len()) {
            return false;
        }
        let mut acc = h_leaf(opening.values[0], opening.values[1]);
        let mut index = pair_index;
        for sibling in &opening.path {
            acc = if index & 1 == 0 {
                h_node(&acc, sibling)
            } else {
                h_node(sibling, &acc)
            };
            index >>= 1;
        }
        &acc == root
    }

    /// Produce a shared Merkle authentication frontier for many queried pair leaves.
    pub fn open_pairs(&self, word: &[F128], indices: &[usize]) -> MerkleMultiOpening {
        assert_eq!(self.levels[0].len() * 2, word.len());
        assert!(!indices.is_empty());
        assert!(indices.windows(2).all(|w| w[0] < w[1]));
        assert!(*indices.last().unwrap() < self.levels[0].len());

        let values = indices
            .iter()
            .map(|&i| [word[2 * i], word[2 * i + 1]])
            .collect::<Vec<_>>();

        let mut auth = Vec::new();
        let mut current = indices.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            for &idx in &current {
                let sibling = idx ^ 1;
                if current.binary_search(&sibling).is_err() {
                    auth.push(level[sibling]);
                }
            }
            current = current.into_iter().map(|i| i >> 1).collect();
            current.dedup();
        }

        MerkleMultiOpening { values, auth }
    }

    /// Verify a canonical shared frontier. `indices` must be sorted and deduplicated.
    pub fn verify_pairs(
        root: &Hash,
        leaf_count: usize,
        indices: &[usize],
        opening: &MerkleMultiOpening,
    ) -> bool {
        if !leaf_count.is_power_of_two()
            || indices.is_empty()
            || opening.values.len() != indices.len()
        {
            return false;
        }
        if *indices.last().unwrap() >= leaf_count {
            return false;
        }
        if !indices.windows(2).all(|w| w[0] < w[1]) {
            return false;
        }

        let mut current: HashMap<usize, Hash> = indices
            .iter()
            .copied()
            .zip(opening.values.iter().map(|v| h_leaf(v[0], v[1])))
            .collect();
        let mut auth_pos = 0usize;

        let depth = leaf_count.trailing_zeros() as usize;
        for _ in 0..depth {
            let mut parents = current.keys().map(|i| i >> 1).collect::<Vec<_>>();
            parents.sort_unstable();
            parents.dedup();
            let mut next = HashMap::with_capacity(parents.len());

            for p in parents {
                let li = p << 1;
                let ri = li | 1;
                let left = if let Some(h) = current.get(&li) {
                    *h
                } else {
                    if auth_pos >= opening.auth.len() {
                        return false;
                    }
                    let h = opening.auth[auth_pos];
                    auth_pos += 1;
                    h
                };
                let right = if let Some(h) = current.get(&ri) {
                    *h
                } else {
                    if auth_pos >= opening.auth.len() {
                        return false;
                    }
                    let h = opening.auth[auth_pos];
                    auth_pos += 1;
                    h
                };
                next.insert(p, h_node(&left, &right));
            }
            current = next;
        }

        auth_pos == opening.auth.len() && current.len() == 1 && current.get(&0) == Some(root)
    }
}

pub fn root_from_pairs(word: &[F128]) -> Hash {
    MerkleTree::from_pairs(word).root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_roundtrip() {
        let word = (0..32).map(F128).collect::<Vec<_>>();
        let tree = MerkleTree::from_pairs(&word);
        for i in 0..16 {
            let op = tree.open_pair(&word, i);
            assert!(MerkleTree::verify_pair(&tree.root(), i, &op));
        }
    }

    #[test]
    fn multiproof_roundtrip() {
        let word = (0..128).map(F128).collect::<Vec<_>>();
        let tree = MerkleTree::from_pairs(&word);
        let indices = vec![0usize, 1, 5, 8, 9, 31, 63];
        let op = tree.open_pairs(&word, &indices);
        assert!(MerkleTree::verify_pairs(
            &tree.root(),
            tree.levels[0].len(),
            &indices,
            &op
        ));
    }

    #[test]
    fn multiproof_tamper_fails() {
        let word = (0..128).map(F128).collect::<Vec<_>>();
        let tree = MerkleTree::from_pairs(&word);
        let indices = vec![2usize, 3, 17, 42];
        let mut op = tree.open_pairs(&word, &indices);
        op.values[0][0] += F128::ONE;
        assert!(!MerkleTree::verify_pairs(
            &tree.root(),
            tree.levels[0].len(),
            &indices,
            &op
        ));
    }
}

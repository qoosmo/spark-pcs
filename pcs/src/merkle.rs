//! SHA-256 Merkle tree. Leaves are byte strings (here: one block = one pair of entries).

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

fn h_leaf(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn h_node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

pub struct MerkleTree {
    levels: Vec<Vec<Hash>>, // levels[0] = leaf hashes, last = [root]
}

impl MerkleTree {
    /// `leaves.len()` must be a power of two.
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        assert!(leaves.len().is_power_of_two());
        let mut levels = vec![leaves.iter().map(|l| h_leaf(l)).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next = prev.chunks(2).map(|c| h_node(&c[0], &c[1])).collect();
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    pub fn open(&self, mut idx: usize) -> Vec<Hash> {
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        for lvl in &self.levels[..self.levels.len() - 1] {
            path.push(lvl[idx ^ 1]);
            idx >>= 1;
        }
        path
    }
}

pub fn verify(root: &Hash, mut idx: usize, leaf: &[u8], path: &[Hash]) -> bool {
    let mut h = h_leaf(leaf);
    for sib in path {
        h = if idx & 1 == 0 {
            h_node(&h, sib)
        } else {
            h_node(sib, &h)
        };
        idx >>= 1;
    }
    idx == 0 && &h == root
}

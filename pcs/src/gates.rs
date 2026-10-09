// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-node gates, derived from a public seed.
//!
//! The gate for variable x_j (1 <= j <= n) at node q in Omega_{n-j} = {0,1}^(k+n-j)
//! is A = [[a,b],[c,d]] with structural points t0 = -a/c, t1 = -b/d. Only (t0, t1)
//! matter for the protocol (the scales c, d act as a public diagonal), so we derive
//! (t0, t1) directly: two distinct field elements from SHA-256(seed, j, q).

use crate::field::{Fp, P, batch_inverse};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub t0: Fp,
    pub t1: Fp,
}

pub fn gate(seed: &[u8; 32], j: usize, q: usize) -> Gate {
    let mut ctr = 0u32;
    loop {
        let mut h = Sha256::new();
        h.update(b"spark-gate");
        h.update(seed);
        h.update((j as u32).to_le_bytes());
        h.update((q as u64).to_le_bytes());
        h.update(ctr.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        let x0 = u64::from_le_bytes(d[0..8].try_into().unwrap());
        let x1 = u64::from_le_bytes(d[8..16].try_into().unwrap());
        if x0 < P && x1 < P && x0 != x1 {
            return Gate {
                t0: Fp(x0),
                t1: Fp(x1),
            };
        }
        ctr += 1;
    }
}

/// All gates of one level, with 1/(t1 - t0) precomputed (prover side).
pub struct LevelGates {
    pub t0: Vec<Fp>,
    pub t1: Vec<Fp>,
    pub inv_diff: Vec<Fp>,
}

pub fn level_gates(seed: &[u8; 32], j: usize, nodes: usize) -> LevelGates {
    let mut t0 = Vec::with_capacity(nodes);
    let mut t1 = Vec::with_capacity(nodes);
    for q in 0..nodes {
        let g = gate(seed, j, q);
        t0.push(g.t0);
        t1.push(g.t1);
    }
    let diffs: Vec<Fp> = t0.iter().zip(&t1).map(|(a, b)| b.sub(*a)).collect();
    let inv_diff = batch_inverse(&diffs);
    LevelGates { t0, t1, inv_diff }
}

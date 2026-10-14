// SPDX-License-Identifier: MIT OR Apache-2.0
//! Brief 19 commit-phase micro-benchmark: builds exactly the Merkle trees the v0.10
//! prover builds (layer 0 over GF(2^128), committed layers over GF(2^256)), with pair
//! leaves (g = 0) and with block leaves (g = d - 1), interleaved in one process.
//! Usage: brief19_commit_microbench <n> <commit_every> <reps>
use spark_binary::{extfield::F256, field::F128, merkle_v05::{HashKind, MerkleTreeV05}};
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: usize = a.get(1).map(|s| s.parse().unwrap()).unwrap_or(20);
    let c: usize = a.get(2).map(|s| s.parse().unwrap()).unwrap_or(3);
    let reps: usize = a.get(3).map(|s| s.parse().unwrap()).unwrap_or(20);
    let k = 2usize;
    let l0 = 1usize << (n + k);
    let mut x: u128 = 0x9e3779b97f4a7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let w0: Vec<F128> = (0..l0).map(|_| F128(next())).collect();
    let mut layers: Vec<(usize, Vec<F256>)> = Vec::new();
    let mut b = c;
    while b < n {
        let d = c.min(n - b);
        let w: Vec<F256> = (0..(l0 >> b)).map(|_| F256 { c0: F128(next()), c1: F128(next()) }).collect();
        layers.push((d, w));
        b += c;
    }
    let d0 = c.min(n);
    let threads = rayon::current_num_threads();
    let run = |block: bool| -> (f64, [u8; 32]) {
        let g = |d: usize| if block { (d - 1) as u32 } else { 0 };
        let t = Instant::now();
        let t0 = MerkleTreeV05::<F128>::from_pairs_grouped(&w0, HashKind::Blake3, g(d0));
        let mut acc = t0.root();
        for (d, w) in &layers {
            let tr = MerkleTreeV05::<F256>::from_pairs_grouped(w, HashKind::Blake3, g(*d));
            acc[0] ^= tr.root()[0];
        }
        (t.elapsed().as_secs_f64() * 1e3, acc)
    };
    // warmup
    let _ = run(false);
    let _ = run(true);
    for r in 0..reps {
        for &block in if r % 2 == 0 { &[false, true] } else { &[true, false] } {
            let (ms, root) = run(block);
            println!(
                "{},{n},{c},{threads},{ms:.3},{:02x}",
                if block { "block" } else { "pair" },
                root[0]
            );
        }
    }
}

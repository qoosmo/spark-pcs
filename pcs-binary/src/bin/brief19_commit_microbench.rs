// SPDX-License-Identifier: MIT OR Apache-2.0
//! Brief 19 commit-phase micro-benchmark: builds exactly the Merkle trees the v0.10
//! prover builds (layer 0 over GF(2^128), committed layers over GF(2^256)), with pair
//! leaves (g = 0) and with block leaves (g = d - 1), interleaved in one process.
//! Usage: brief19_commit_microbench <n> <commit_every> <reps>
use spark_binary::{extfield::F256, field::F128, merkle_v05::{HashKind, Layout, MerkleTreeV05}};
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
    // mode 0 = rc1 (pair leaves, prefixed); 1 = group leaves, prefixed; 2 = v0.10 (group, keyed)
    let run = |mode: u8| -> (f64, [u8; 32]) {
        let lay = |d: usize| match mode {
            0 => Layout::PAIR,
            1 => Layout { group_log: (d - 1) as u32, keyed: false },
            _ => Layout::v10((d - 1) as u32),
        };
        let t = Instant::now();
        let t0 = MerkleTreeV05::<F128>::with_layout(&w0, HashKind::Blake3, lay(d0));
        let mut acc = t0.root();
        for (d, w) in &layers {
            let tr = MerkleTreeV05::<F256>::with_layout(w, HashKind::Blake3, lay(*d));
            acc[0] ^= tr.root()[0];
        }
        (t.elapsed().as_secs_f64() * 1e3, acc)
    };
    for m in 0..3u8 {
        let _ = run(m); // warmup
    }
    let names = ["pair", "block", "v10"];
    for r in 0..reps {
        let order: [u8; 3] = if r % 2 == 0 { [0, 1, 2] } else { [2, 1, 0] };
        for m in order {
            let (ms, root) = run(m);
            println!("{},{n},{c},{threads},{ms:.3},{:02x}", names[m as usize], root[0]);
        }
    }
}

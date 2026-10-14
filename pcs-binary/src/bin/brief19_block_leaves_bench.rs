// SPDX-License-Identifier: MIT OR Apache-2.0
//! Brief 19 benchmark: pair leaves (default) vs block leaves (`--features block-leaves`).
//! Usage: brief19_block_leaves_bench <n> <commit_every> <runs> [warmups]
//! Prints one CSV row per measured run.
use spark_binary::{
    encode::{GateFamily, V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER, V10_TPLUS1_PUBLIC_GATE_SEED},
    field::F128,
    merkle_v05::HashKind,
    protocol_sparse_v10::prove_and_verify_sparse_v10,
    transcript_v10::ParamsV10,
};

const DOMAIN_LEAF: usize = 22; // "SPARK-BINARY-LEAF-v0.5"
const DOMAIN_NODE: usize = 22; // "SPARK-BINARY-NODE-v0.5"
const DOMAIN_BLOCK: usize = 21; // "SPARK-BINARY-BLOCK-v1"

fn blake3_compressions(len: usize) -> u64 {
    // Single-chunk messages (<= 1024 bytes): one compression per 64-byte block.
    assert!(len <= 1024);
    len.div_ceil(64).max(1) as u64
}

/// (hash calls, compressions) for one tree over `elems` elements of `size` bytes,
/// with `2^g` pairs per leaf.
fn tree_cost(elems: usize, size: usize, g: u32) -> (u64, u64) {
    let pairs = elems / 2;
    let leaves = (pairs >> g) as u64;
    let leaf_len = if g == 0 {
        DOMAIN_LEAF + 2 * size
    } else {
        DOMAIN_BLOCK + (2usize << g) * size
    };
    let calls = leaves + (leaves - 1);
    let comp = leaves * blake3_compressions(leaf_len) + (leaves - 1) * blake3_compressions(DOMAIN_NODE + 64);
    (calls, comp)
}

fn commit_cost(n: usize, k: usize, c: usize, block: bool) -> (u64, u64) {
    let l0 = 1usize << (n + k);
    let g = |d: usize| if block { (d - 1) as u32 } else { 0 };
    let (mut calls, mut comp) = tree_cost(l0, 16, g(c.min(n)));
    let mut b = c;
    while b < n {
        let d = c.min(n - b);
        let (a, cc) = tree_cost(l0 >> b, 32, g(d));
        calls += a;
        comp += cc;
        b += c;
    }
    (calls, comp)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(20);
    let c: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(3);
    let runs: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(5);
    let warm: usize = args.get(4).map(|s| s.parse().unwrap()).unwrap_or(1);
    let block = cfg!(feature = "block-leaves");
    let variant = if block { "block" } else { "pair" };

    let p = ParamsV10 {
        n,
        k: 2,
        i0: 3,
        s: 407,
        g: 16,
        t: 1,
        commit_every: c,
        gate_seed: V10_TPLUS1_PUBLIC_GATE_SEED,
        setup_counter: V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    };
    p.validate().expect("params");
    let fam = GateFamily::from_seed_and_counter(p.n, p.k, p.gate_seed, p.setup_counter);
    let coeffs = (0..(1usize << n))
        .map(|i| F128((i as u128) ^ ((i as u128).wrapping_mul(0x9e3779b97f4a7c15))))
        .collect::<Vec<_>>();
    let (calls, comp) = commit_cost(n, p.k, c, block);
    let threads = rayon::current_num_threads();

    for r in 0..(warm + runs) {
        let t = prove_and_verify_sparse_v10(&coeffs, &fam, &p).expect("prove/verify");
        assert!(t.verified);
        if r < warm {
            continue;
        }
        let ms = |d: std::time::Duration| d.as_secs_f64() * 1e3;
        let core = t.encode + t.commit0 + t.fold_total + t.commit_folds + t.query_open;
        println!(
            "{variant},{n},{c},{threads},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{}",
            ms(t.encode),
            ms(t.commit0),
            ms(t.fold_total),
            ms(t.commit_folds),
            ms(t.query_open),
            ms(t.grind),
            ms(core),
            ms(t.prover_total()),
            ms(t.verify_total()),
            t.proof.serialized_size_bytes(),
            calls,
            comp
        );
    }
}

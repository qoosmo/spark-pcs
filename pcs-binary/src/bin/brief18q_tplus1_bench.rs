// SPDX-License-Identifier: MIT OR Apache-2.0
#[cfg(not(feature = "tplus1"))]
use spark_binary::encode::{V09_N20_K2_I0_3_SETUP_COUNTER, V09_PUBLIC_GATE_SEED};
#[cfg(feature = "tplus1")]
use spark_binary::encode::{V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER, V10_TPLUS1_PUBLIC_GATE_SEED};
use spark_binary::{
    encode::GateFamily, field::F128, merkle_v05::HashKind,
    protocol_sparse_v06::prove_and_verify_sparse_v09, security::soundness_bits_from,
    transcript_v09::ParamsV09,
};
use std::time::Instant;

#[cfg(feature = "tplus1")]
fn gate_config() -> (&'static str, u64, u64) {
    (
        "tplus1",
        V10_TPLUS1_PUBLIC_GATE_SEED,
        V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER,
    )
}

#[cfg(not(feature = "tplus1"))]
fn gate_config() -> (&'static str, u64, u64) {
    (
        "random-pair",
        V09_PUBLIC_GATE_SEED,
        V09_N20_K2_I0_3_SETUP_COUNTER,
    )
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let n = args
        .get(1)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(20);
    let m = args
        .get(2)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(3);
    let k = 2usize;
    let i0 = 3usize;
    let g = 16u32;
    let (gate_family, seed, pinned_counter) = gate_config();

    let sec = soundness_bits_from(n, k, 128.0, 256.0, g as f64, 64.0, i0);

    let setup_start = Instant::now();
    let checked = GateFamily::from_seed_checked_i0_3(n, k, seed);
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1e3;
    assert_eq!(
        checked.counter, pinned_counter,
        "checked setup counter changed for {gate_family}"
    );

    let params = ParamsV09 {
        n,
        k,
        i0,
        s: sec.s,
        g,
        t: 1,
        commit_every: m,
        gate_seed: seed,
        setup_counter: checked.counter,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    };
    params.validate().unwrap();

    let coeffs = (0..(1usize << n))
        .map(|i| F128((i as u128) ^ (i as u128).wrapping_mul(0x9e3779b97f4a7c15u128)))
        .collect::<Vec<_>>();

    let out = prove_and_verify_sparse_v09(&coeffs, &checked.family, &params).unwrap();
    assert!(out.verified);

    let commit_ms = (out.commit0 + out.commit_folds).as_secs_f64() * 1e3;

    println!("EXPERIMENTAL_ONLY=true");
    println!("gate_family={gate_family}");
    println!("n={n}");
    println!("k={k}");
    println!("i0={i0}");
    println!("m={m}");
    println!("g={g}");
    println!("s={}", sec.s);
    println!("seed={seed}");
    println!("setup_counter={}", checked.counter);
    println!("setup_ms={setup_ms:.3}");
    println!("encode_ms={:.3}", out.encode.as_secs_f64() * 1e3);
    println!("commit_ms={commit_ms:.3}");
    println!("commit0_ms={:.3}", out.commit0.as_secs_f64() * 1e3);
    println!(
        "commit_folds_ms={:.3}",
        out.commit_folds.as_secs_f64() * 1e3
    );
    println!("fold_ms={:.3}", out.fold_total.as_secs_f64() * 1e3);
    println!("openings_ms={:.3}", out.query_open.as_secs_f64() * 1e3);
    println!("grind_ms={:.3}", out.grind.as_secs_f64() * 1e3);
    println!("prover_ms={:.3}", out.prover_total().as_secs_f64() * 1e3);
    println!("verify_ms={:.3}", out.verify_total().as_secs_f64() * 1e3);
    println!("proof_bytes={}", out.proof.serialized_size_bytes());
    println!("verified={}", out.verified);
}

// SPDX-License-Identifier: MIT OR Apache-2.0
use rand::{rngs::StdRng, SeedableRng};
use spark_binary::{
    encode::GateFamily, field::F128, merkle_v05::HashKind,
    protocol_sparse_v06::prove_and_verify_sparse_v06, security::soundness_bits_from,
};
use std::time::Instant;

fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    if a.len() < 3 {
        eprintln!(
            "usage: spark-binary <n> <k> [grind_bits=0] [blake3|sha256] [seed=1] [commit_every=1]"
        );
        std::process::exit(2);
    }
    let n: usize = a[1].parse().unwrap();
    let k: usize = a[2].parse().unwrap();
    let grind: u32 = a.get(3).map(|x| x.parse().unwrap()).unwrap_or(0);
    let hash = HashKind::parse(a.get(4).map(String::as_str).unwrap_or("blake3"));
    let seed: u64 = a.get(5).map(|x| x.parse().unwrap()).unwrap_or(1);
    let commit_every: usize = a.get(6).map(|x| x.parse().unwrap()).unwrap_or(1);
    assert!(commit_every >= 1 && commit_every <= n);

    let sec = soundness_bits_from(n, k, 128.0, 256.0, grind as f64, 64.0, 3);
    let mut rng = StdRng::seed_from_u64(seed ^ 0x535041524b);
    let coeffs = (0..(1usize << n))
        .map(|_| F128::random(&mut rng))
        .collect::<Vec<_>>();

    let t = Instant::now();
    let checked = GateFamily::from_seed_checked_i0_3(n, k, seed);
    let setup = t.elapsed();
    let setup_counter = checked.counter;
    let setup_check = checked.check_time;
    let family = checked.family;
    let out = prove_and_verify_sparse_v06(
        &coeffs,
        &family,
        seed,
        setup_counter,
        sec.s,
        grind,
        commit_every,
        hash,
    );

    println!("SPARK binary prototype v0.7 (sparse commitments + real grinding)");
    println!(
        "n={n} k={k} queries={} grind_bits={grind} commit_every={commit_every} hash={} coeffs={} encoded_len={}",
        sec.s,
        hash.name(),
        1usize << n,
        1usize << (n + k)
    );
    println!("challenge_field_bits=256");
    println!("gate_field_bits=128");
    println!("checked_setup_i0=3");
    println!("setup_counter={setup_counter}");
    println!("delta_code={:.6}", sec.delta_code);
    println!("delta={:.6}", sec.delta);
    println!("gamma={:.6}", sec.gamma);
    println!("M={}", sec.m);
    println!("N1={}", sec.n1);
    println!("eps_log2={:.3}", sec.eps.log2());
    println!("target_bits={:.3}", sec.target_bits);
    println!("fold_term_bits={:.3}", sec.fold_bits);
    println!("per_query_bits={:.6}", sec.per_query_bits);
    println!("query_term_bits={:.3}", sec.query_bits);
    println!("setup_check_ms={:.3}", setup_check.as_secs_f64() * 1e3);
    println!("setup_ms={:.3}", setup.as_secs_f64() * 1e3);
    println!("encode_ms={:.3}", out.encode.as_secs_f64() * 1e3);
    println!("commit0_ms={:.3}", out.commit0.as_secs_f64() * 1e3);
    println!(
        "commit_total_ms={:.3}",
        out.commit_total().as_secs_f64() * 1e3
    );
    println!("fold_ms={:.3}", out.fold_total.as_secs_f64() * 1e3);
    println!("fold_commit_ms={:.3}", out.commit_folds.as_secs_f64() * 1e3);
    println!("grind_ms={:.3}", out.grind.as_secs_f64() * 1e3);
    println!(
        "grind_nonce={}",
        out.proof
            .grind_nonce
            .map(|x| x.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("query_open_ms={:.3}", out.query_open.as_secs_f64() * 1e3);
    println!("open_total_ms={:.3}", out.open_total().as_secs_f64() * 1e3);
    println!(
        "prover_total_ms={:.3}",
        out.prover_total().as_secs_f64() * 1e3
    );
    println!(
        "verify_gate_derive_ms={:.3}",
        out.gate_derive_verify.as_secs_f64() * 1e3
    );
    println!(
        "verify_gate_prf_ms={:.3}",
        out.gate_prf_verify.as_secs_f64() * 1e3
    );
    println!(
        "verify_gate_batch_inverse_ms={:.3}",
        out.gate_batch_inverse_verify.as_secs_f64() * 1e3
    );
    println!(
        "verify_gate_build_ms={:.3}",
        out.gate_build_verify.as_secs_f64() * 1e3
    );
    println!(
        "verify_checks_ms={:.3}",
        out.verify_checks.as_secs_f64() * 1e3
    );
    println!(
        "verify_transcript_ms={:.3}",
        out.verify_transcript.as_secs_f64() * 1e3
    );
    println!(
        "verify_merkle_ms={:.3}",
        out.verify_merkle.as_secs_f64() * 1e3
    );
    println!(
        "verify_folding_ms={:.3}",
        out.verify_folding.as_secs_f64() * 1e3
    );
    println!(
        "verify_other_ms={:.3}",
        out.verify_other.as_secs_f64() * 1e3
    );
    println!("verify_ms={:.3}", out.verify_total().as_secs_f64() * 1e3);
    println!("proof_bytes={}", out.proof.serialized_size_bytes());
    println!(
        "proof_kib={:.3}",
        out.proof.serialized_size_bytes() as f64 / 1024.0
    );
    println!("verified={}", out.verified);
}

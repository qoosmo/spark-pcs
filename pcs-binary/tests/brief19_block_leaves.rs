// SPDX-License-Identifier: MIT OR Apache-2.0
#![cfg(feature = "block-leaves")]
use spark_binary::{
    encode::{GateFamily, V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER, V10_TPLUS1_PUBLIC_GATE_SEED},
    field::F128,
    merkle_v05::HashKind,
    protocol_sparse_v10::{prove_and_verify_sparse_v10, verify_sparse_v10},
    transcript_v10::ParamsV10,
};

fn params(n: usize, c: usize) -> ParamsV10 {
    ParamsV10 {
        n,
        k: 2,
        i0: 3,
        s: 407,
        g: 4,
        t: 1,
        commit_every: c,
        gate_seed: V10_TPLUS1_PUBLIC_GATE_SEED,
        setup_counter: V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    }
}

fn coeffs(n: usize) -> Vec<F128> {
    (0..(1usize << n))
        .map(|i| F128((i as u128) ^ ((i as u128).wrapping_mul(0x9e3779b97f4a7c15))))
        .collect()
}

#[test]
fn block_leaves_round_trip_and_tamper() {
    for n in [8usize, 10, 12] {
        for c in [2usize, 3, 4] {
            let p = params(n, c);
            if p.validate().is_err() {
                continue;
            }
            let fam = GateFamily::from_seed_and_counter(p.n, p.k, p.gate_seed, p.setup_counter);
            let run = prove_and_verify_sparse_v10(&coeffs(n), &fam, &p).expect("honest proof verifies");
            assert!(run.verified);
            assert_eq!(run.proof.proof_format_version, 11, "block-leaves format byte");

            // Tamper with a first-layer opened value.
            let mut bad = run.proof.clone();
            bad.body.opening0.values[0][0] = F128(bad.body.opening0.values[0][0].0 ^ 1);
            assert!(verify_sparse_v10(&p, &run.commitment, &bad).is_err(), "n={n} c={c} opening0");

            // Tamper with a first-layer authentication digest.
            if !run.proof.body.opening0.auth.is_empty() {
                let mut bad = run.proof.clone();
                bad.body.opening0.auth[0][0] ^= 1;
                assert!(verify_sparse_v10(&p, &run.commitment, &bad).is_err(), "n={n} c={c} auth0");
            }

            // Tamper with a committed-layer opening (value or digest).
            if let Some(op) = run.proof.body.folded_openings.first() {
                let mut bad = run.proof.clone();
                if !op.values.is_empty() {
                    let v = bad.body.folded_openings[0].values[0];
                    bad.body.folded_openings[0].values[0] = v + spark_binary::extfield::F256::ONE;
                } else if !op.auth.is_empty() {
                    bad.body.folded_openings[0].auth[0][0] ^= 1;
                } else {
                    // fully derived and fully deduplicated: tamper the root instead
                    bad.body.folded_roots[0][0] ^= 1;
                }
                assert!(verify_sparse_v10(&p, &run.commitment, &bad).is_err(), "n={n} c={c} folded");
            }

            // A proof claiming the pair-leaf format byte is rejected.
            let mut bad = run.proof.clone();
            bad.proof_format_version = 10;
            assert!(verify_sparse_v10(&p, &run.commitment, &bad).is_err(), "n={n} c={c} version");
        }
    }
}

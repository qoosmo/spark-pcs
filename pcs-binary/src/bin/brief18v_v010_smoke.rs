use spark_binary::{
    encode::{GateFamily, V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER, V10_TPLUS1_PUBLIC_GATE_SEED},
    field::F128,
    merkle_v05::HashKind,
    protocol_sparse_v06::{prove_and_verify_sparse_v09, verify_sparse_v09},
    protocol_sparse_v10::{prove_and_verify_sparse_v10, verify_sparse_v10},
    transcript_v09::ParamsV09,
    transcript_v10::ParamsV10,
};

fn main() {
    let p10 = ParamsV10 {
        n: 20,
        k: 2,
        i0: 3,
        s: 407,
        g: 16,
        t: 1,
        commit_every: 3,
        gate_seed: V10_TPLUS1_PUBLIC_GATE_SEED,
        setup_counter: V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    };
    p10.validate().unwrap();

    let p09 = ParamsV09 {
        n: 20,
        k: 2,
        i0: 3,
        s: 407,
        g: 16,
        t: 1,
        commit_every: 3,
        gate_seed: V10_TPLUS1_PUBLIC_GATE_SEED,
        setup_counter: V10_TPLUS1_N20_K2_I0_3_SETUP_COUNTER,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    };
    p09.validate().unwrap();

    let h10 = p10.header().unwrap().serialize();
    let h09 = p09.header().unwrap().serialize();
    assert_eq!(h10.len(), 157);
    assert_ne!(h10, h09);

    let fam = GateFamily::from_seed_and_counter(p10.n, p10.k, p10.gate_seed, p10.setup_counter);

    let coeffs = (0..(1usize << 20))
        .map(|i| F128((i as u128) ^ ((i as u128).wrapping_mul(0x9e3779b97f4a7c15))))
        .collect::<Vec<_>>();

    let run10 = prove_and_verify_sparse_v10(&coeffs, &fam, &p10).unwrap();
    assert!(run10.verified);
    let bytes10 = run10.proof.serialized_size_bytes();

    println!("V010_PROOF_BYTES={bytes10}");
    println!("V010_HEADER_BYTES={}", h10.len());
    println!("V010_SETUP_COUNTER={}", p10.setup_counter);

    let expect10 = if cfg!(feature = "rc1-layout") { 594218 } else { 591562 };
    assert_eq!(bytes10, expect10);
    assert_eq!(p10.setup_counter, 0);
    println!("V010_PINNED_SMOKE=PASS");

    let run09 = prove_and_verify_sparse_v09(&coeffs, &fam, &p09).unwrap();
    assert!(run09.verified);
    let bytes09 = run09.proof.serialized_size_bytes();
    println!("V09_TPLUS1_PROOF_BYTES={bytes09}");
    assert_eq!(bytes09, 592577);

    // Cross-rejection without crossing Rust module types:
    // feed the v0.9 header/version into an otherwise well-typed v0.10 proof.
    let mut wrong10 = run10.proof.clone();
    wrong10.proof_format_version = run09.proof.proof_format_version;
    wrong10.header = run09.proof.header.clone();
    assert!(verify_sparse_v10(&p10, &run10.commitment, &wrong10).is_err());

    // And symmetrically feed the v0.10 header/version to the v0.9 verifier.
    let mut wrong09 = run09.proof.clone();
    wrong09.proof_format_version = run10.proof.proof_format_version;
    wrong09.header = run10.proof.header.clone();
    assert!(verify_sparse_v09(&p09, &run09.commitment, &wrong09).is_err());

    println!("V010_CROSS_REJECTION=PASS");
}

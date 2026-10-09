use spark_binary::{
    encode::{
        GateFamily,
        V09_N20_K2_I0_3_SETUP_COUNTER,
        V09_PUBLIC_GATE_SEED,
    },
    field::F128,
    merkle_v05::HashKind,
    protocol_sparse_v06::prove_and_verify_sparse_v09,
    security::soundness_bits_from,
    transcript_v09::ParamsV09,
};

fn main() {
    let n = 20usize;
    let k = 2usize;
    let i0 = 3usize;
    let g = 16u32;
    let m = 3usize;

    let sec = soundness_bits_from(
        n,
        k,
        128.0,
        256.0,
        g as f64,
        64.0,
        i0,
    );

    let params = ParamsV09 {
        n,
        k,
        i0,
        s: sec.s,
        g,
        t: 1,
        commit_every: m,
        gate_seed: V09_PUBLIC_GATE_SEED,
        setup_counter: V09_N20_K2_I0_3_SETUP_COUNTER,
        hash_kind: HashKind::Blake3,
        target_bits: 192,
    };

    params.validate().unwrap();

    let family = GateFamily::from_seed_and_counter(
        n,
        k,
        V09_PUBLIC_GATE_SEED,
        V09_N20_K2_I0_3_SETUP_COUNTER,
    );

    let coeffs = (0..(1usize << n))
        .map(|i| {
            F128(
                (i as u128)
                    ^ (i as u128)
                        .wrapping_mul(0x9e3779b97f4a7c15u128),
            )
        })
        .collect::<Vec<_>>();

    let out =
        prove_and_verify_sparse_v09(&coeffs, &family, &params).unwrap();

    assert!(out.verified);

    let header_bytes = params.header().unwrap().serialize().len();
    let wrapper_bytes = 1 + 4 + header_bytes;

    println!("verified={}", out.verified);
    println!("seed={}", V09_PUBLIC_GATE_SEED);
    println!("setup_counter={}", V09_N20_K2_I0_3_SETUP_COUNTER);
    println!("s={}", params.s);
    println!("fold_term_bits={:.3}", sec.fold_bits);
    println!("query_term_bits={:.3}", sec.query_bits);
    println!("prover_ms={:.3}", out.prover_total().as_secs_f64() * 1000.0);
    println!("verifier_ms={:.3}", out.verify_total().as_secs_f64() * 1000.0);
    println!("proof_bytes={}", out.proof.serialized_size_bytes());
    println!("proof_kib={:.6}", out.proof.serialized_size_bytes() as f64 / 1024.0);
    println!("header_bytes={}", header_bytes);
    println!("wrapper_bytes={}", wrapper_bytes);
}

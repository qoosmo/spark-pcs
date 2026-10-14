// SPDX-License-Identifier: MIT OR Apache-2.0
//! v0.10 release smoke test: both named profiles on the pinned public setup.
use spark_binary::{
    encode::GateFamily,
    field::F128,
    protocol_sparse_v10::{prove_and_verify_sparse_v10, verify_sparse_v10},
    transcript_v10::{ParamsV10, ProfileV10, PROOF_FORMAT_VERSION_V10},
};

fn main() {
    let pinned = std::env::args().nth(1).as_deref() != Some("--print");
    let coeffs = (0..(1usize << 20))
        .map(|i| F128((i as u128) ^ ((i as u128).wrapping_mul(0x9e3779b97f4a7c15))))
        .collect::<Vec<_>>();
    for (prof, expect) in [(ProfileV10::Compact, 591_562usize), (ProfileV10::Fast, 647_522usize)] {
        let p = ParamsV10::profile(prof);
        p.validate().expect("profile validates");
        let fam = GateFamily::from_seed_and_counter(p.n, p.k, p.gate_seed, p.setup_counter);
        let run = prove_and_verify_sparse_v10(&coeffs, &fam, &p).expect("prove/verify");
        assert!(run.verified);
        assert_eq!(run.proof.proof_format_version, PROOF_FORMAT_VERSION_V10);
        let bytes = run.proof.serialized_size_bytes();
        println!("V010_{}_PROOF_BYTES={bytes}", prof.name().to_uppercase());
        if pinned && expect != 0 {
            assert_eq!(bytes, expect);
        }
        // A proof for one profile does not verify under the other.
        let other = ParamsV10::profile(match prof {
            ProfileV10::Compact => ProfileV10::Fast,
            ProfileV10::Fast => ProfileV10::Compact,
        });
        assert!(verify_sparse_v10(&other, &run.commitment, &run.proof).is_err());
    }
    println!("V010_PROFILES_SMOKE=PASS");
}

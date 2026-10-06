use spark_pcs::field::Fp;
use spark_pcs::params::Params;
use spark_pcs::pcs::{commit, eval_multilinear, proof_size_bytes, prove, verify};
use std::time::Instant;

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let n = *args.first().unwrap_or(&16);
    let k = *args.get(1).unwrap_or(&6);
    let params = Params::new(n, k, 128.0, [42u8; 32]).unwrap_or_else(|e| panic!("{e}"));
    println!("n = {n}, k = {k} (table 2^{} = {} entries)", n + k, 1u64 << (n + k));
    println!(
        "certified Delta* = {:.4}, delta = {:.4}, queries s = {}, log2 bad-challenge term = {:.1}",
        params.delta_star, params.delta, params.s, params.log2_bad_challenge
    );
    let coeffs: Vec<Fp> = (0..1u64 << n).map(|i| Fp::new(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 12345)).collect();

    let t = Instant::now();
    let (root, committed) = commit(&params, &coeffs);
    let t_commit = t.elapsed();

    let t = Instant::now();
    let (y, z, proof) = prove(&params, &committed);
    let t_prove = t.elapsed();

    let t = Instant::now();
    let res = verify(&params, &root, &proof);
    let t_verify = t.elapsed();

    let (y2, _) = res.expect("verification failed");
    assert_eq!(y, y2);
    assert_eq!(y, eval_multilinear(&coeffs, &z), "opened value differs from F(z)");
    println!("commit  {:>9.3} s", t_commit.as_secs_f64());
    println!("prove   {:>9.3} s", t_prove.as_secs_f64());
    println!("verify  {:>9.3} ms", t_verify.as_secs_f64() * 1e3);
    println!("proof   {:>9.1} KiB", proof_size_bytes(&proof) as f64 / 1024.0);
    println!("y = F(z) checked against direct evaluation: OK");
}

// SPDX-License-Identifier: MIT OR Apache-2.0
use spark_binary::security::soundness_bits_from;

fn arg_usize(args: &[String], name: &str, default: usize) -> usize {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].parse().unwrap())
        .unwrap_or(default)
}
fn arg_f64(args: &[String], name: &str, default: f64) -> f64 {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].parse().unwrap())
        .unwrap_or(default)
}
fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    let n = arg_usize(&a, "--n", 20);
    let k = arg_usize(&a, "--k", 2);
    let i0 = arg_usize(&a, "--i0", 3);
    let g = arg_f64(&a, "--g", 16.0);
    let target = arg_f64(&a, "--target", 192.0);
    let q_bits = target - 128.0;
    assert!(q_bits >= 0.0);
    let r = soundness_bits_from(n, k, 128.0, 256.0, g, q_bits, i0);
    println!("n={n}");
    println!("k={k}");
    println!("i0={i0}");
    println!("g={g:.0}");
    println!("target_bits={:.3}", r.target_bits);
    println!("Delta_star={:.10}", r.delta_code);
    println!("delta={:.10}", r.delta);
    println!("gamma={:.10}", r.gamma);
    println!("M={}", r.m);
    println!("N1={}", r.n1);
    println!("eps={:.17e}", r.eps);
    println!("eps_log2={:.3}", r.eps.log2());
    println!("s={}", r.s);
    println!("fold_term_bits={:.3}", r.fold_bits);
    println!("query_term_bits={:.3}", r.query_bits);
}

#[cfg(test)]
mod tests {
    use spark_binary::security::soundness_bits_from;
    #[test]
    fn v08_n20_pinned() {
        let r = soundness_bits_from(20, 2, 128.0, 256.0, 16.0, 64.0, 3);
        assert!((r.delta_code - 0.6157093048).abs() < 1e-9);
        assert!((r.delta - 0.259320).abs() < 1e-5);
        assert!((r.gamma - 0.035815).abs() < 1e-5);
        assert_eq!(r.m, 4);
        assert_eq!(r.n1, 545);
        assert_eq!(r.s, 407);
        assert!((r.fold_bits - 192.008).abs() < 0.02);
        assert!((r.query_bits - 192.263).abs() < 0.05);
    }
}

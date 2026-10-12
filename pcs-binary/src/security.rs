// SPDX-License-Identifier: MIT OR Apache-2.0
#[derive(Clone, Copy, Debug)]
pub struct SecurityReport {
    pub delta_code: f64,
    pub delta: f64,
    pub gamma: f64,
    pub m: usize,
    pub n1: usize,
    pub eps: f64,
    pub fold_bits: f64,
    pub per_query_bits: f64,
    pub query_bits: f64,
    pub s: usize,
    pub target_bits: f64,
}

fn log_gamma(z: f64) -> f64 {
    // Lanczos, adequate for benchmark parameter selection.
    const P: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.5203681218851,
        -1259.1392167224028,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507343278686905,
        -0.13857109526572012,
        9.984369578019571e-6,
        1.5056327351493116e-7,
    ];
    if z < 0.5 {
        return std::f64::consts::PI.ln()
            - (std::f64::consts::PI * z).sin().ln()
            - log_gamma(1.0 - z);
    }
    let z = z - 1.0;
    let mut x = P[0];
    for (i, p) in P.iter().enumerate().skip(1) {
        x += p / (z + i as f64);
    }
    let t = z + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + x.ln()
}
fn log2_binom(n: usize, k: usize) -> f64 {
    if k > n {
        return f64::INFINITY;
    }
    (log_gamma((n + 1) as f64) - log_gamma((k + 1) as f64) - log_gamma((n - k + 1) as f64))
        / std::f64::consts::LN_2
}

/// Checked-setup rank-saturation certificate starting from an MDS prefix C_i0.
/// Theorem 3.19 permits any checked i0.
pub fn certified_delta_from(n: usize, k: usize, log2q_gates: f64, lambda: f64, i0: usize) -> f64 {
    assert!(i0 >= 1 && n >= i0);
    let levels = n - i0;
    let per = lambda + (levels as f64).log2().ceil();
    let mut z = 1usize << i0; // checked C2 is MDS: Z_2=D_2=4.
    for i in (i0 + 1)..=n {
        let l = 1usize << (k + i);
        let max_g = l.saturating_sub(2 * z);
        let mut chosen = None;
        for g in 0..=max_g {
            let zi = 2 * z + g;
            // log2[ C(L,Z)/(q-1) q^-g ], (1+1/q)^L is negligible at q=2^128.
            let logp = log2_binom(l, zi) - log2q_gates - g as f64 * log2q_gates;
            if logp <= -per {
                chosen = Some(zi);
                break;
            }
        }
        z = chosen.expect("distance certificate search failed");
    }
    1.0 - (z.saturating_sub(1) as f64) / ((1usize << (k + n)) as f64)
}

pub fn certified_delta(n: usize, k: usize, log2q_gates: f64, lambda: f64) -> f64 {
    certified_delta_from(n, k, log2q_gates, lambda, 2)
}

/// Optimize epsilon on a log2 grid to minimize s under Theorem 6.4.
/// target = 128 for interactive; for Fiat-Shamir use 128+log2Q.
pub fn soundness_bits_from(
    n: usize,
    k: usize,
    log2q_gates: f64,
    log2k: f64,
    grind: f64,
    log2q_hash: f64,
    i0: usize,
) -> SecurityReport {
    let delta_code = certified_delta_from(n, k, log2q_gates, 128.0, i0);
    let dmax = (1.0 - (1.0 - delta_code).powf(1.0 / 3.0)).min(delta_code / 2.0);
    let delta = 0.95 * dmax;
    let gamma = ((1.0 - delta).powi(3) - (1.0 - delta_code)) / delta_code;
    // Brief 11b / revised Lemma 6.2 absorption constant:
    // once a line carries M decoded points, every close challenge lies on it.
    let m = (delta / (delta_code - 2.0 * delta)).floor() as usize + 2;
    let n1 = ((12.0 / (delta_code * gamma)).max(2.0 * m as f64 / gamma + 2.0)).ceil() as usize;
    let target = 128.0 + log2q_hash;
    let mut best = None;
    // eps = 2^x.  Fine enough to reproduce expected query counts.
    let mut x = -80.0;
    while x <= -1.0 {
        let eps = 2f64.powf(x);
        let base = 1.0 - delta + n as f64 * eps;
        if base < 1.0 {
            let log2sum = (n as f64).log2() + ((n1 as f64) + 1.0 / eps).log2();
            let fold_bits = log2k - log2sum;
            if fold_bits >= target {
                let per = -base.log2();
                let need = (target - grind).max(0.0);
                let s = (need / per).ceil() as usize;
                match best {
                    None => best = Some((s, eps, fold_bits, per)),
                    Some((bs, _, _, _)) if s < bs => best = Some((s, eps, fold_bits, per)),
                    _ => {}
                }
            }
        }
        x += 0.01;
    }
    let (s, eps, fold_bits, per_query_bits) = best.expect("no epsilon satisfies fold target");
    SecurityReport {
        delta_code,
        delta,
        gamma,
        m,
        n1,
        eps,
        fold_bits,
        per_query_bits,
        query_bits: s as f64 * per_query_bits + grind,
        s,
        target_bits: target,
    }
}

pub fn soundness_bits(
    n: usize,
    k: usize,
    log2q_gates: f64,
    log2k: f64,
    grind: f64,
    log2q_hash: f64,
) -> SecurityReport {
    soundness_bits_from(n, k, log2q_gates, log2k, grind, log2q_hash, 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn brief_values_match() {
        let d2 = certified_delta(20, 2, 128.0, 128.0);
        let d3 = certified_delta(20, 3, 128.0, 128.0);
        assert!((d2 - 0.582).abs() < 0.002, "{d2}");
        assert!((d3 - 0.757).abs() < 0.002, "{d3}");
        let r = soundness_bits(20, 2, 128.0, 256.0, 0.0, 64.0);
        assert!((r.s as isize - 486).abs() <= 2, "{}", r.s);
        let rg = soundness_bits(20, 2, 128.0, 256.0, 24.0, 64.0);
        assert!((rg.s as isize - 425).abs() <= 2, "{}", rg.s);
    }

    #[test]
    fn brief10_i0_3_and_future_prefix_values() {
        let d3 = certified_delta_from(20, 2, 128.0, 128.0, 3);
        let d4 = certified_delta_from(20, 2, 128.0, 128.0, 4);
        let d5 = certified_delta_from(20, 2, 128.0, 128.0, 5);
        assert!((d3 - 0.6157093048).abs() < 1e-9, "{d3}");
        assert!((d4 - 0.6343445778).abs() < 1e-9, "{d4}");
        assert!((d5 - 0.6428670883).abs() < 1e-9, "{d5}");

        let r = soundness_bits_from(20, 2, 128.0, 256.0, 16.0, 64.0, 3);
        assert!((r.s as isize - 407).abs() <= 1, "{}", r.s);
    }

    #[test]
    fn brief11b_absorption_constant_regression() {
        let r2 = soundness_bits_from(20, 2, 128.0, 256.0, 16.0, 64.0, 2);
        assert_eq!(r2.m, 4, "i0=2 new absorption M");
        assert_eq!(r2.n1, 558, "i0=2 N1 must remain unchanged");

        let r3 = soundness_bits_from(20, 2, 128.0, 256.0, 16.0, 64.0, 3);
        assert_eq!(r3.m, 4, "i0=3 new absorption M");
        assert_eq!(r3.n1, 545, "i0=3 N1 must remain unchanged");
        assert_eq!(r3.s, 407, "i0=3 query count remains 407");
        assert!(r3.fold_bits >= 192.0, "fold term must meet 192-bit target");
    }
}

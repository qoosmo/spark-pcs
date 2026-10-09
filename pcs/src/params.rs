// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security parameters from the spec (Theorem 3.10 distance bound, Lemma 6.2, Theorem 6.4).

#[derive(Clone, Debug)]
pub struct Params {
    pub n: usize,                // number of variables
    pub k: usize,                // redundancy bits: table size 2^(n+k)
    pub s: usize,                // number of queries
    pub seed: [u8; 32],          // public gate seed
    pub delta_star: f64,         // certified relative distance
    pub delta: f64,              // proximity threshold used in the soundness theorem
    pub log2_bad_challenge: f64, // log2 of n (N_1 + 1/eps) / |K|
}

/// Theorem 3.10 with C(N,s) <= (eN/s)^s: certified Delta* with setup failure <= 2^-lambda.
pub fn distance_bound(log2q: f64, n: usize, k: usize, lambda: f64) -> f64 {
    let target = -(lambda + (n as f64).log2());
    let mut loss = 0.0;
    for i in 1..=n {
        let l = (1u64 << (k + i - 1)) as f64;
        let d = (1u64 << (i - 1)) as f64;
        let mut s = 1.0f64;
        loop {
            let lb = 2.0 * d * log2q + s * ((std::f64::consts::E * l / s).log2() + 1.0 - log2q);
            if lb <= target {
                break;
            }
            s += 1.0;
            if s > l {
                return f64::NAN;
            }
        }
        loss += s / (2.0 * l);
    }
    1.0 - loss
}

impl Params {
    /// Goldilocks gates (log2 q = 64), challenges in the cubic extension (log2 |K| ~ 192).
    pub fn new(n: usize, k: usize, lambda: f64, seed: [u8; 32]) -> Result<Params, String> {
        let a = distance_bound(64.0, n, k, lambda);
        let b = distance_bound_saturation(64.0, n, k, lambda);
        let delta_star = if a.is_nan() {
            b
        } else if b.is_nan() {
            a
        } else {
            a.max(b)
        };
        if delta_star.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
            return Err(format!(
                "k = {k} gives no certified distance at n = {n}; increase k"
            ));
        }
        let delta_max = (1.0 - (1.0 - delta_star).powf(1.0 / 3.0)).min(delta_star / 2.0);
        let delta = 0.95 * delta_max;
        let eps = 2f64.powi(-30);
        let gamma = ((1.0 - delta).powi(3) - (1.0 - delta_star)) / delta_star;
        let m = (delta_star / (delta_star - 2.0 * delta)).floor() + 1.0;
        let n1 = (12.0 / (delta_star * gamma))
            .max(2.0 * m / gamma + 2.0)
            .ceil();
        let log2_bad = (n as f64 * (n1 + 1.0 / eps)).log2() - 3.0 * 64.0;
        let per_query = 1.0 - delta + n as f64 * eps;
        let s = (lambda / -per_query.log2()).ceil() as usize;
        Ok(Params {
            n,
            k,
            s,
            seed,
            delta_star,
            delta,
            log2_bad_challenge: log2_bad,
        })
    }
}

fn h2(x: f64) -> f64 {
    if x <= 0.0 || x >= 1.0 {
        0.0
    } else {
        -x * x.log2() - (1.0 - x) * (1.0 - x).log2()
    }
}

/// Theorem 3.14 (rank saturation): Z_0 = 1, Z_i = 2 Z_{i-1} + g_i with g_i minimal such that
/// C(L_i, Z_i) (1+1/q)^{L_{i-1}} q^{-g_i} / (q-1) <= 2^-lambda / n. Returns 1 - (Z_n - 1)/L_n.
pub fn distance_bound_saturation(log2q: f64, n: usize, k: usize, lambda: f64) -> f64 {
    let target = -(lambda + (n as f64).log2());
    let mut z_prev = 1.0f64;
    for i in 1..=n {
        let l = 2f64.powi((k + i) as i32);
        let small = (l / 2.0) * std::f64::consts::LOG2_E * 2f64.powf(-log2q);
        let cost = |g: f64| -> f64 {
            let z = 2.0 * z_prev + g;
            if z > l {
                return f64::INFINITY;
            }
            l * h2(z / l) + small - (g + 1.0) * log2q + 1e-9
        };
        let mut hi = (l - 2.0 * z_prev).max(0.0);
        if cost(hi) > target {
            return f64::NAN;
        }
        let mut lo = 0.0f64;
        while hi - lo > 0.5 {
            let mid = ((lo + hi) / 2.0).floor();
            if cost(mid) <= target {
                hi = mid;
            } else {
                lo = mid + 1.0;
            }
        }
        if cost(lo) <= target {
            hi = lo;
        }
        z_prev = 2.0 * z_prev + hi;
    }
    1.0 - (z_prev - 1.0) / 2f64.powi((k + n) as i32)
}

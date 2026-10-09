#![allow(
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::ptr_arg
)]

// Experiments for the matrix-gate folding code.
//
// Code C_i (i variables, k redundancy bits), length L_i = 2^(k+i), positions packed as
// pos = 2*q + b with q a position of C_(i-1), b in {0,1}.
//   Enc_0(c)            = (c, ..., c)                                  (length 2^k)
//   Enc_i(F)[2q + b]    = Enc_(i-1)(u)[q] + t_i^b[q] * Enc_(i-1)(v)[q],  F = u + x_1 v
// Coefficient vectors: index bit 0 <-> first variable x_1 (folded first).

use std::env;

// ---------- small prime field ----------
#[derive(Clone, Copy)]
struct Fp {
    p: u64,
}
impl Fp {
    fn add(&self, a: u64, b: u64) -> u64 {
        let s = a as u128 + b as u128;
        (if s >= self.p as u128 {
            s - self.p as u128
        } else {
            s
        }) as u64
    }
    fn sub(&self, a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { a + self.p - b }
    }
    fn mul(&self, a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % self.p as u128) as u64
    }
    fn pow(&self, mut a: u64, mut e: u64) -> u64 {
        let mut r = 1u64;
        while e > 0 {
            if e & 1 == 1 {
                r = self.mul(r, a);
            }
            a = self.mul(a, a);
            e >>= 1;
        }
        r
    }
    fn inv(&self, a: u64) -> u64 {
        assert!(a % self.p != 0);
        self.pow(a, self.p - 2)
    }
}

// ---------- rng ----------
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, m: u64) -> u64 {
        self.next() % m
    }
}

// gates[i-1] = (t0, t1) for layer i, each of length L_(i-1) = 2^(k+i-1)
type Gates = Vec<(Vec<u64>, Vec<u64>)>;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    PerNode,  // fresh distinct pair for every node
    PerLayer, // one pair per layer, shared by all nodes
}

fn sample_gates(f: &Fp, n: usize, k: usize, mode: Mode, rng: &mut Rng) -> Gates {
    let mut g = Vec::new();
    for i in 1..=n {
        let len = 1usize << (k + i - 1);
        let mut t0 = vec![0u64; len];
        let mut t1 = vec![0u64; len];
        let (s0, s1) = distinct_pair(f, rng);
        for q in 0..len {
            let (a, b) = if mode == Mode::PerNode {
                distinct_pair(f, rng)
            } else {
                (s0, s1)
            };
            t0[q] = a;
            t1[q] = b;
        }
        g.push((t0, t1));
    }
    g
}

fn distinct_pair(f: &Fp, rng: &mut Rng) -> (u64, u64) {
    loop {
        let a = rng.below(f.p);
        let b = rng.below(f.p);
        if a != b {
            return (a, b);
        }
    }
}

fn encode(f: &Fp, coeffs: &[u64], k: usize, gates: &Gates) -> Vec<u64> {
    let i = coeffs.len().trailing_zeros() as usize;
    if i == 0 {
        return vec![coeffs[0]; 1 << k];
    }
    let u: Vec<u64> = coeffs.iter().step_by(2).cloned().collect();
    let v: Vec<u64> = coeffs.iter().skip(1).step_by(2).cloned().collect();
    let eu = encode(f, &u, k, gates);
    let ev = encode(f, &v, k, gates);
    let (t0, t1) = &gates[i - 1];
    let mut out = vec![0u64; eu.len() * 2];
    for q in 0..eu.len() {
        out[2 * q] = f.add(eu[q], f.mul(t0[q], ev[q]));
        out[2 * q + 1] = f.add(eu[q], f.mul(t1[q], ev[q]));
    }
    out
}

// one folding round: word of C_i (len 2L) -> word of C_(i-1) (len L)
fn fold(f: &Fp, w: &[u64], z: u64, t0: &[u64], t1: &[u64]) -> Vec<u64> {
    let l = w.len() / 2;
    (0..l)
        .map(|q| {
            let (w0, w1) = (w[2 * q], w[2 * q + 1]);
            let lam = f.mul(f.sub(z, t0[q]), f.inv(f.sub(t1[q], t0[q])));
            f.add(w0, f.mul(lam, f.sub(w1, w0)))
        })
        .collect()
}

// evaluate multilinear (coeff index bit j <-> variable x_(j+1)) at point
fn eval_ml(f: &Fp, coeffs: &[u64], point: &[u64]) -> u64 {
    let mut acc = 0u64;
    for (idx, &c) in coeffs.iter().enumerate() {
        let mut m = c;
        for (j, &x) in point.iter().enumerate() {
            if (idx >> j) & 1 == 1 {
                m = f.mul(m, x);
            }
        }
        acc = f.add(acc, m);
    }
    acc
}

// point r(theta) for a position of C_n
fn point_of(n: usize, pos: usize, gates: &Gates) -> Vec<u64> {
    // pos at level n = 2*q_(n-1) + b_n ; coordinate x_1 uses gates[n-1] at q_(n-1), etc.
    let mut r = vec![0u64; n];
    let mut cur = pos;
    for j in 0..n {
        let layer = n - j; // gates index layer-1
        let b = cur & 1;
        let q = cur >> 1;
        let (t0, t1) = &gates[layer - 1];
        r[j] = if b == 0 { t0[q] } else { t1[q] };
        cur = q;
    }
    r
}

fn verify_identities() {
    for p in [(1u64 << 31) - 1, 0xFFFF_FFFF_0000_0001] {
        let f = Fp { p };
        let mut rng = Rng(7);
        let (n, k) = (5usize, 2usize);
        let mut ok = true;
        for _trial in 0..20 {
            let gates = sample_gates(&f, n, k, Mode::PerNode, &mut rng);
            let coeffs: Vec<u64> = (0..1 << n).map(|_| rng.below(f.p)).collect();
            let cw = encode(&f, &coeffs, k, &gates);
            // closed form: Enc_n(F)[theta] = F(r(theta))
            for pos in 0..cw.len() {
                let r = point_of(n, pos, &gates);
                if eval_ml(&f, &coeffs, &r) != cw[pos] {
                    ok = false;
                }
            }
            // folding with z_1..z_n gives constant F(z)
            let z: Vec<u64> = (0..n).map(|_| rng.below(f.p)).collect();
            let mut w = cw.clone();
            let mut cur = coeffs.clone();
            for j in 0..n {
                let layer = n - j;
                let (t0, t1) = &gates[layer - 1];
                w = fold(&f, &w, z[j], t0, t1);
                // fold maps Enc_i(u + x v) to Enc_(i-1)(u + z v)
                let u: Vec<u64> = cur.iter().step_by(2).cloned().collect();
                let v: Vec<u64> = cur.iter().skip(1).step_by(2).cloned().collect();
                cur = u
                    .iter()
                    .zip(v.iter())
                    .map(|(&a, &b)| f.add(a, f.mul(z[j], b)))
                    .collect();
                if w != encode(&f, &cur, k, &gates) {
                    ok = false;
                }
            }
            let y = eval_ml(&f, &coeffs, &z);
            if !w.iter().all(|&x| x == y) {
                ok = false;
            }
            // gate form of the fold: random A = [[a,b],[c,d]] with t0=-a/c, t1=-b/d
            for _ in 0..50 {
                let (c, d) = (1 + rng.below(f.p - 1), 1 + rng.below(f.p - 1));
                let (t0, t1) = distinct_pair(&f, &mut rng);
                let a = f.sub(0, f.mul(t0, c));
                let b = f.sub(0, f.mul(t1, d));
                let det = f.sub(f.mul(a, d), f.mul(b, c));
                assert!(det != 0);
                let (uu, vv, zz) = (rng.below(f.p), rng.below(f.p), rng.below(f.p));
                let w0 = f.add(uu, f.mul(t0, vv));
                let w1 = f.add(uu, f.mul(t1, vv));
                let di = f.inv(det);
                let l = f.mul(f.mul(d, di), w1); // L = (d/det) w1
                let rr = f.sub(0, f.mul(f.mul(c, di), w0)); // R = -(c/det) w0
                let e = f.add(
                    f.mul(f.add(a, f.mul(c, zz)), l),
                    f.mul(f.add(b, f.mul(d, zz)), rr),
                );
                if e != f.add(uu, f.mul(zz, vv)) {
                    ok = false;
                }
                // gamma(1) = +det/d : W2(t1) = a + c t1
                if f.add(a, f.mul(c, t1)) != f.mul(det, f.inv(d)) {
                    ok = false;
                }
                // gamma(0) = -det/c : W3(t0) = b + d t0
                if f.add(b, f.mul(d, t0)) != f.sub(0, f.mul(det, f.inv(c))) {
                    ok = false;
                }
            }
        }
        println!(
            "[p={}] identity checks (closed form, fold, final value, gate form, gammas): {}",
            p,
            if ok { "PASS" } else { "FAIL" }
        );
    }
    verify_kronecker();
}

// Original-document facts: decomposition tree with per-layer gates A_1..A_n
// (layer 1 splits x_n, children L = F_{2j}, R = F_{2j+1}), leaves T0 in heap order.
// Check alpha = (A_1 (x) ... (x) A_n) T0 (A_1 on the most significant index bit)
// and H(F) = (r(A_1) (x) ... (x) r(A_n)) T0 with r(A) = [2a+c, 2b+d].
fn verify_kronecker() {
    let f = Fp {
        p: (1u64 << 31) - 1,
    };
    let mut rng = Rng(77);
    let mut ok = true;
    for _ in 0..20 {
        let n = 4usize;
        let gates: Vec<[u64; 4]> = (0..n)
            .map(|_| {
                loop {
                    let g = [
                        rng.below(f.p),
                        rng.below(f.p),
                        rng.below(f.p),
                        rng.below(f.p),
                    ];
                    if f.sub(f.mul(g[0], g[3]), f.mul(g[1], g[2])) != 0 {
                        break g;
                    }
                }
            })
            .collect();
        let alpha: Vec<u64> = (0..1 << n).map(|_| rng.below(f.p)).collect();
        // decompose: node polynomial in i vars, split top var: F = u + x v, (u,v) = A (L,R)
        let mut level = vec![alpha.clone()];
        for (layer, g) in gates.iter().enumerate() {
            let [a, b, c, d] = *g;
            let det_inv = f.inv(f.sub(f.mul(a, d), f.mul(b, c)));
            let half = 1usize << (n - layer - 1);
            let mut next = Vec::new();
            for poly in &level {
                let u = &poly[..half];
                let v = &poly[half..];
                let l: Vec<u64> = (0..half)
                    .map(|t| f.mul(det_inv, f.sub(f.mul(d, u[t]), f.mul(b, v[t]))))
                    .collect();
                let r: Vec<u64> = (0..half)
                    .map(|t| f.mul(det_inv, f.sub(f.mul(a, v[t]), f.mul(c, u[t]))))
                    .collect();
                next.push(l);
                next.push(r);
            }
            level = next;
        }
        let t0: Vec<u64> = level.iter().map(|p| p[0]).collect();
        // Kronecker product applied: index bits, A_1 on msb
        let mut kron = vec![0u64; 1 << n];
        let mut sum_row = vec![0u64; 1 << n];
        for row in 0..1usize << n {
            for col in 0..1usize << n {
                let mut m = 1u64;
                for (layer, g) in gates.iter().enumerate() {
                    let bit = n - 1 - layer;
                    let (rb, cb) = ((row >> bit) & 1, (col >> bit) & 1);
                    m = f.mul(m, g[2 * rb + cb]);
                }
                kron[row] = f.add(kron[row], f.mul(m, t0[col]));
            }
        }
        if kron != alpha {
            ok = false;
        }
        for col in 0..1usize << n {
            let mut m = 1u64;
            for (layer, g) in gates.iter().enumerate() {
                let bit = n - 1 - layer;
                let cb = (col >> bit) & 1;
                let r = if cb == 0 {
                    f.add(f.add(g[0], g[0]), g[2])
                } else {
                    f.add(f.add(g[1], g[1]), g[3])
                };
                m = f.mul(m, r);
            }
            sum_row[col] = m;
        }
        let s_dot: u64 =
            (0..1usize << n).fold(0, |acc, col| f.add(acc, f.mul(sum_row[col], t0[col])));
        // hypercube sum directly
        let mut h = 0u64;
        for x in 0..1usize << n {
            let pt: Vec<u64> = (0..n).map(|j| ((x >> j) & 1) as u64).collect();
            h = f.add(h, eval_ml(&f, &alpha, &pt));
        }
        if s_dot != h {
            ok = false;
        }
    }
    println!(
        "Kronecker + sum-row checks (alpha = (A_1 x..x A_n) T0, H = (x r(A_i)) T0): {}",
        if ok { "PASS" } else { "FAIL" }
    );
}

// exhaustive minimum distance of C_n over F_q
fn min_distance(f: &Fp, n: usize, k: usize, gates: &Gates) -> usize {
    let dim = 1usize << n;
    let rows: Vec<Vec<u64>> = (0..dim)
        .map(|r| {
            let mut e = vec![0u64; dim];
            e[r] = 1;
            encode(f, &e, k, gates)
        })
        .collect();
    let len = rows[0].len();
    let mut cw = vec![0u64; len];
    let mut digits = vec![0u64; dim];
    let mut best = len;
    loop {
        // odometer increment: add row j; carrying digit wraps (q * row = 0)
        let mut j = 0;
        loop {
            if j == dim {
                return best;
            }
            for (x, &r) in cw.iter_mut().zip(rows[j].iter()) {
                *x = f.add(*x, r);
            }
            digits[j] += 1;
            if digits[j] == f.p {
                digits[j] = 0;
                j += 1;
            } else {
                break;
            }
        }
        let w = cw.iter().filter(|&&x| x != 0).count();
        if w < best {
            best = w;
        }
    }
}

// provable lower bound on relative distance (Lemma: per-layer loss s_i / (2 L_(i-1)))
fn distance_bound(log2q: f64, n: usize, k: usize, lambda: f64) -> f64 {
    let target = -(lambda + (n as f64).log2());
    let mut loss = 0.0;
    for i in 1..=n {
        let l = (1u64 << (k + i - 1)) as f64;
        let d = (1u64 << (i - 1)) as f64;
        // find minimal s with log2( q^(2D) * C(L,s) * (2/q)^s ) <= target, C(L,s) <= (eL/s)^s
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "bound" {
        println!("provable relative-distance bound, lambda = 128 (setup failure <= 2^-128)");
        println!("{:>6} {:>3} {:>3} {:>10}", "log2q", "n", "k", "Delta>=");
        for &lq in &[31.0f64, 64.0, 124.0] {
            for &n in &[16usize, 20, 24] {
                for &k in &[2usize, 3, 4, 5, 6] {
                    println!(
                        "{:>6} {:>3} {:>3} {:>10.4}",
                        lq,
                        n,
                        k,
                        distance_bound(lq, n, k, 128.0)
                    );
                }
            }
        }
        return;
    }
    if args.len() > 1 && args[1] == "vand" {
        exp_vandermonde_circuit();
        return;
    }
    if args.len() > 1 && args[1] == "checked" {
        checked_setup_table();
        return;
    }
    if args.len() > 1 && args[1] == "coll" {
        exp_collision();
        return;
    }
    if args.len() > 1 && args[1] == "mdsx" {
        exp_mds_exhaustive();
        return;
    }
    if args.len() > 1 && args[1] == "p1" {
        exp_problem1();
        return;
    }
    if args.len() > 1 && args[1] == "p2" {
        exp_problem2();
        return;
    }
    if args.len() > 1 && args[1] == "sanity2" {
        bound2_sanity();
        return;
    }
    if args.len() > 1 && args[1] == "bound2" {
        bound2_table();
        return;
    }
    if args.len() > 1 && args[1] == "isd" {
        if args.len() > 2 && args[2] == "gl" {
            isd_experiment(0xFFFF_FFFF_0000_0001, "Goldilocks");
        } else {
            isd_experiment((1u64 << 31) - 1, "M31");
        }
        return;
    }
    if args.len() > 1 && args[1] == "sweep" {
        println!("per-node gates, n = 2: effect of field size (4 samples)");
        println!(
            "{:>3} {:>2} {:>6} {:>8} {:>8} {:>10}",
            "q", "k", "len", "min", "mean", "1-2^-k"
        );
        let mut rng = Rng(999);
        for &p in &[13u64, 31, 61] {
            for k in 1..=3usize {
                let f = Fp { p };
                let ds: Vec<usize> = (0..4)
                    .map(|_| {
                        let g = sample_gates(&f, 2, k, Mode::PerNode, &mut rng);
                        min_distance(&f, 2, k, &g)
                    })
                    .collect();
                let len = (1usize << (2 + k)) as f64;
                println!(
                    "{:>3} {:>2} {:>6} {:>8.4} {:>8.4} {:>10.4}",
                    p,
                    k,
                    len as usize,
                    *ds.iter().min().unwrap() as f64 / len,
                    ds.iter().sum::<usize>() as f64 / 4.0 / len,
                    1.0 - 0.5f64.powi(k as i32)
                );
            }
        }
        return;
    }
    verify_identities();
    if args.len() > 1 && args[1] == "ident" {
        return;
    }
    println!();
    println!("exhaustive minimum distance (relative), 6 random gate samples each");
    println!(
        "{:>3} {:>2} {:>2} {:>9} {:>6} {:>10} {:>10} {:>10}",
        "q", "n", "k", "mode", "len", "min", "mean", "max"
    );
    let cases: Vec<(u64, usize, usize)> = vec![
        (13, 2, 1),
        (13, 2, 2),
        (13, 2, 3),
        (7, 3, 1),
        (7, 3, 2),
        (7, 3, 3),
        (3, 4, 1),
        (3, 4, 2),
    ];
    let mut rng = Rng(12345);
    for &(p, n, k) in &cases {
        let f = Fp { p };
        for &mode in &[Mode::PerNode, Mode::PerLayer] {
            let mut ds = Vec::new();
            for _ in 0..6 {
                let g = sample_gates(&f, n, k, mode, &mut rng);
                ds.push(min_distance(&f, n, k, &g));
            }
            let len = (1usize << (n + k)) as f64;
            let mn = *ds.iter().min().unwrap() as f64 / len;
            let mx = *ds.iter().max().unwrap() as f64 / len;
            let mean = ds.iter().sum::<usize>() as f64 / ds.len() as f64 / len;
            let name = if mode == Mode::PerNode {
                "per-node"
            } else {
                "per-layer"
            };
            println!(
                "{:>3} {:>2} {:>2} {:>9} {:>6} {:>10.4} {:>10.4} {:>10.4}",
                p, n, k, name, len as usize, mn, mean, mx
            );
        }
    }
}

// ---------------- Fix 3 experiment: distance at realistic field size ----------------
// A nonzero codeword can vanish on at most D-1 positions iff every D-subset of columns
// is independent (Singleton / MDS). We (1) test D-subsets for rank deficiency, random
// and structured (unions of whole subtrees, which is where the tree structure could
// hurt), and (2) run an information-set search: pick D-1 positions, take the codeword
// vanishing there, count its zeros. More than D-1 zeros = weaker than Singleton.

fn column(f: &Fp, n: usize, pos: usize, gates: &Gates) -> Vec<u64> {
    let r = point_of(n, pos, gates);
    let d = 1usize << n;
    let mut m = vec![1u64; d];
    for idx in 1..d {
        let j = idx.trailing_zeros() as usize;
        m[idx] = f.mul(m[idx & (idx - 1)], r[j]);
    }
    m
}

// row-reduce `rows` (each len d) in place; returns rank and pivot columns
fn rref(f: &Fp, rows: &mut Vec<Vec<u64>>, d: usize) -> (usize, Vec<usize>) {
    let mut rank = 0;
    let mut pivots = Vec::new();
    for col in 0..d {
        if rank == rows.len() {
            break;
        }
        let piv = (rank..rows.len()).find(|&r| rows[r][col] != 0);
        let Some(p) = piv else { continue };
        rows.swap(rank, p);
        let inv = f.inv(rows[rank][col]);
        for x in rows[rank].iter_mut() {
            *x = f.mul(*x, inv);
        }
        let prow = rows[rank].clone();
        for r in 0..rows.len() {
            if r != rank && rows[r][col] != 0 {
                let c = rows[r][col];
                for (x, &y) in rows[r].iter_mut().zip(prow.iter()) {
                    *x = f.sub(*x, f.mul(c, y));
                }
            }
        }
        pivots.push(col);
        rank += 1;
    }
    (rank, pivots)
}

// structured subset: aligned subtree blocks of random sizes until `count` positions
fn structured_subset(n: usize, k: usize, count: usize, rng: &mut Rng) -> Vec<usize> {
    let len = 1usize << (n + k);
    let mut taken = vec![false; len];
    let mut out = Vec::new();
    while out.len() < count {
        let j = rng.below((n + 1) as u64) as usize; // block = subtree of 2^j leaves
        let size = 1usize << j;
        let start = (rng.below((len / size) as u64) as usize) * size;
        for p in start..start + size {
            if out.len() == count {
                break;
            }
            if !taken[p] {
                taken[p] = true;
                out.push(p);
            }
        }
    }
    out
}

fn random_subset(len: usize, count: usize, rng: &mut Rng) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..len).collect();
    for i in 0..count {
        let j = i + rng.below((len - i) as u64) as usize;
        idx.swap(i, j);
    }
    idx.truncate(count);
    idx
}

fn isd_experiment(p: u64, name: &str) {
    let f = Fp { p };
    let mut rng = Rng(2026);
    println!(
        "field {}, per-node random gates (control: per-layer gates)",
        name
    );
    println!(
        "{:>2} {:>2} {:>6} {:>5} {:>9} {:>11} {:>11} {:>12} {:>12}",
        "n", "k", "len", "D", "mode", "sing.rand", "sing.struct", "max zeros", "Delta found"
    );
    let configs = [
        (6usize, 1usize, 300usize),
        (6, 2, 300),
        (6, 3, 300),
        (8, 1, 120),
        (8, 2, 120),
        (8, 3, 120),
    ];
    for &(n, k, trials) in &configs {
        for &mode in &[Mode::PerNode, Mode::PerLayer] {
            if mode == Mode::PerLayer && n > 6 {
                continue;
            }
            let gates = sample_gates(&f, n, k, mode, &mut rng);
            let len = 1usize << (n + k);
            let d = 1usize << n;
            let cols: Vec<Vec<u64>> = (0..len).map(|p| column(&f, n, p, &gates)).collect();
            let mut sing_rand = 0;
            let mut sing_struct = 0;
            let mut max_zeros = 0usize;
            for t in 0..trials {
                // rank tests on D-subsets
                let s_r = random_subset(len, d, &mut rng);
                let mut m: Vec<Vec<u64>> = s_r.iter().map(|&p| cols[p].clone()).collect();
                if rref(&f, &mut m, d).0 < d {
                    sing_rand += 1;
                }
                let s_s = structured_subset(n, k, d, &mut rng);
                let mut m: Vec<Vec<u64>> = s_s.iter().map(|&p| cols[p].clone()).collect();
                if rref(&f, &mut m, d).0 < d {
                    sing_struct += 1;
                }
                // information-set search: codeword vanishing on D-1 chosen positions
                let zs = if t % 2 == 0 {
                    structured_subset(n, k, d - 1, &mut rng)
                } else {
                    random_subset(len, d - 1, &mut rng)
                };
                let mut m: Vec<Vec<u64>> = zs.iter().map(|&p| cols[p].clone()).collect();
                let (rank, pivots) = rref(&f, &mut m, d);
                let free = (0..d).find(|c| !pivots.contains(c)).unwrap();
                let mut coeffs = vec![0u64; d];
                coeffs[free] = 1;
                for (r, &pc) in pivots.iter().enumerate().take(rank) {
                    coeffs[pc] = f.sub(0, m[r][free]);
                }
                let cw = encode(&f, &coeffs, k, &gates);
                let zeros = cw.iter().filter(|&&x| x == 0).count();
                max_zeros = max_zeros.max(zeros);
            }
            let name = if mode == Mode::PerNode {
                "per-node"
            } else {
                "per-layer"
            };
            println!(
                "{:>2} {:>2} {:>6} {:>5} {:>9} {:>7}/{:<3} {:>7}/{:<3} {:>5} (D-1={:<3}) {:>6.4}",
                n,
                k,
                len,
                d,
                name,
                sing_rand,
                trials,
                sing_struct,
                trials,
                max_zeros,
                d - 1,
                1.0 - max_zeros as f64 / len as f64
            );
        }
        let len = (1usize << (n + k)) as f64;
        let d = (1usize << n) as f64;
        println!(
            "{:>48} Singleton limit Delta = {:.4}",
            "",
            1.0 - (d - 1.0) / len
        );
    }
}

// ---------- Distance theorem v2 (rank-saturation induction) ----------
// e_i = 2 e_{i-1} + g_i, with g_i minimal such that
//   C(L_i, Z_i) * (1+1/q)^{L_i} * q/(q-1) * q^{-(g_i+1)} <= 2^{-lambda} / n,   Z_i = D_i + 2 e_{i-1} + g_i.
// Conclusion: every nonzero codeword of C_n has fewer than D_n + e_n zeros.
fn h2(x: f64) -> f64 {
    if x <= 0.0 || x >= 1.0 {
        0.0
    } else {
        -x * x.log2() - (1.0 - x) * (1.0 - x).log2()
    }
}

fn distance_bound_v2(log2q: f64, n: usize, k: usize, lambda: f64) -> f64 {
    let target = -(lambda + (n as f64).log2());
    let mut e = 0.0f64;
    for i in 1..=n {
        let l = 2f64.powi((k + i) as i32);
        let d = 2f64.powi(i as i32);
        let cost = |g: f64| -> f64 {
            let z = d + 2.0 * e + g;
            if z > l {
                return f64::INFINITY;
            }
            // log2 C(L,Z) <= L H(Z/L);  (1+1/q)^L and q/(q-1) are negligible but kept
            l * h2(z / l) + l * std::f64::consts::LOG2_E * 2f64.powf(-log2q) + 1e-9
                - (g + 1.0) * log2q
        };
        let (mut lo, mut hi) = (0.0f64, (l - d - 2.0 * e).max(0.0));
        if cost(hi) > target {
            return f64::NAN;
        }
        while hi - lo > 0.5 {
            let mid = ((lo + hi) / 2.0).floor();
            if cost(mid) <= target {
                hi = mid;
            } else {
                lo = mid + 1.0;
                if cost(lo) <= target {
                    hi = lo;
                    break;
                }
            }
        }
        e = 2.0 * e + hi;
        if d + e > l {
            return f64::NAN;
        }
    }
    let l = 2f64.powi((k + n) as i32);
    let d = 2f64.powi(n as i32);
    1.0 - (d + e - 1.0) / l
}

pub fn bound2_table() {
    println!("Distance theorem v2: certified Delta (setup failure <= 2^-128), and PCS queries s");
    println!(
        "{:>14} {:>3} {:>3} {:>8} {:>8} {:>6} | old Delta",
        "field(log2 q)", "n", "k", "Delta", "delta", "s"
    );
    for &(name, lq) in &[
        ("M31 31", 31.0f64),
        ("Goldilocks 64", 64.0),
        ("GL^3 192", 192.0),
    ] {
        for &n in &[16usize, 20, 24] {
            for &k in &[2usize, 3, 4, 5, 6] {
                let dl = distance_bound_v2(lq, n, k, 128.0);
                let old = distance_bound(lq, n, k, 128.0);
                if dl.is_nan() || dl <= 0.0 {
                    println!(
                        "{:>14} {:>3} {:>3} {:>8} {:>8} {:>6} | {:.3}",
                        name, n, k, "-", "-", "-", old
                    );
                    continue;
                }
                let dmax = (1.0 - (1.0 - dl).powf(1.0 / 3.0)).min(dl / 2.0);
                let delta = 0.95 * dmax;
                let s = (128.0 / -(1.0 - delta).log2()).ceil();
                println!(
                    "{:>14} {:>3} {:>3} {:>8.4} {:>8.4} {:>6} | {:.3}",
                    name, n, k, dl, delta, s, old
                );
            }
        }
    }
}

pub fn bound2_sanity() {
    // certified (with failure prob <= 2^-lambda) vs exhaustive minimum over random gate samples
    let mut rng = Rng(4242);
    for &(p, n, k) in &[(61u64, 2usize, 3usize), (61, 2, 2), (31, 2, 3), (13, 2, 3)] {
        let f = Fp { p };
        let lq = (p as f64).log2();
        let cert = distance_bound_v2(lq, n, k, 2.0); // failure <= 1/4 (per the union bound)
        let mut below = 0;
        let trials = 12;
        let mut mn = 1.0f64;
        for _ in 0..trials {
            let g = sample_gates(&f, n, k, Mode::PerNode, &mut rng);
            let d = min_distance(&f, n, k, &g) as f64 / (1usize << (n + k)) as f64;
            mn = mn.min(d);
            if d + 1e-12 < cert {
                below += 1;
            }
        }
        println!(
            "q={p:>3} n={n} k={k}: certified (fail<=1/4) {cert:.4}, exhaustive min over {trials} samples {mn:.4}, samples below certificate: {below}"
        );
    }
}

// ======================= Problem 1 experiment =======================
// Pr[columns of a D-subset S are dependent] over random per-node gates, normalized by (q-1).
// A uniformly random D x D matrix gives ~1. Growth with n would indicate a per-level effect.
pub fn exp_problem1() {
    let mut rng = Rng(777);
    println!("Problem 1: (q-1) * Pr[D-subset singular]  (random matrix ~ 1.0); k = 1");
    println!(
        "{:>4} {:>2} {:>5} {:>7} {:>10} {:>10} {:>12}",
        "q", "n", "D", "trials", "random S", "subtree S", "|S|=D+1 (x(q-1)^2)"
    );
    for &p in &[31u64, 61, 127] {
        let f = Fp { p };
        for n in 2..=7usize {
            let k = 1usize;
            let d = 1usize << n;
            let len = 1usize << (n + k);
            let trials = if n <= 5 { 6000 } else { 2500 };
            let (mut sr, mut ss, mut s1) = (0usize, 0usize, 0usize);
            for _ in 0..trials {
                let gates = sample_gates(&f, n, k, Mode::PerNode, &mut rng);
                let cols: Vec<Vec<u64>> = (0..len).map(|pos| column(&f, n, pos, &gates)).collect();
                let s = random_subset(len, d, &mut rng);
                let mut m: Vec<Vec<u64>> = s.iter().map(|&x| cols[x].clone()).collect();
                if rref(&f, &mut m, d).0 < d {
                    sr += 1;
                }
                let s = structured_subset(n, k, d, &mut rng);
                let mut m: Vec<Vec<u64>> = s.iter().map(|&x| cols[x].clone()).collect();
                if rref(&f, &mut m, d).0 < d {
                    ss += 1;
                }
                let s = random_subset(len, d + 1, &mut rng);
                let mut m: Vec<Vec<u64>> = s.iter().map(|&x| cols[x].clone()).collect();
                if rref(&f, &mut m, d).0 < d {
                    s1 += 1;
                }
            }
            let qm = (p - 1) as f64;
            println!(
                "{:>4} {:>2} {:>5} {:>7} {:>10.3} {:>10.3} {:>12.3}",
                p,
                n,
                d,
                trials,
                sr as f64 / trials as f64 * qm,
                ss as f64 / trials as f64 * qm,
                s1 as f64 / trials as f64 * qm * qm
            );
        }
    }
}

// ======================= Problem 2 experiment =======================
// Exhaustive over all pairs (A,B) modulo C^2 (i.e. over syndrome pairs) for small random codes.
// For each error budget t (delta*N = t): close(A,B) = #{z in F_q : dist(A + zB, C) <= t};
// e*(A,B) = interleaved distance of (A,B) to C^2. Report, for each t and each e* > t,
// the maximum number of close z. Correlated agreement at radius t predicts: many close z
// force e* <= t * M/(M-1).
pub fn exp_problem2() {
    let mut rng = Rng(31337);
    let want_mds = std::env::args().nth(2).as_deref() == Some("mds");
    let shapes: Vec<(u64, usize, usize)> = if want_mds {
        vec![(7, 6, 2), (7, 7, 3), (11, 6, 2)]
    } else {
        vec![(7, 6, 2), (7, 7, 3), (7, 8, 4), (5, 8, 3)]
    };
    for &(p, n_len, kdim) in &shapes {
        let f = Fp { p };
        let r = n_len - kdim;
        let nsyn = (p as usize).pow(r as u32);
        for trial in 0..2 {
            // random parity-check matrix H (r x N), full rank
            let hcols: Vec<Vec<u64>> = loop {
                let cols: Vec<Vec<u64>> = (0..n_len)
                    .map(|_| (0..r).map(|_| rng.below(p)).collect())
                    .collect();
                let mut m: Vec<Vec<u64>> = (0..r)
                    .map(|i| cols.iter().map(|c| c[i]).collect())
                    .collect();
                if rref(&f, &mut m, n_len).0 == r && (!want_mds || is_mds(&f, &cols, r)) {
                    break cols;
                }
            };
            let enc = |v: &[u64]| -> usize {
                v.iter()
                    .rev()
                    .fold(0usize, |acc, &x| acc * p as usize + x as usize)
            };
            let dec = |mut idx: usize| -> Vec<u64> {
                (0..r)
                    .map(|_| {
                        let d = (idx % p as usize) as u64;
                        idx /= p as usize;
                        d
                    })
                    .collect()
            };
            // span bitsets for every subset T of positions, processed by increasing |T|
            let mut subsets: Vec<usize> = (0..1usize << n_len).collect();
            subsets.sort_by_key(|t| t.count_ones());
            let mut span: Vec<Vec<bool>> = vec![Vec::new(); 1 << n_len];
            for &t in &subsets {
                if t == 0 {
                    let mut s = vec![false; nsyn];
                    s[0] = true;
                    span[0] = s;
                    continue;
                }
                let j = t.trailing_zeros() as usize;
                let prev = &span[t & (t - 1)];
                let mut s = vec![false; nsyn];
                for (idx, &b) in prev.iter().enumerate() {
                    if !b {
                        continue;
                    }
                    let v = dec(idx);
                    for c in 0..p {
                        let w: Vec<u64> =
                            (0..r).map(|i| f.add(v[i], f.mul(c, hcols[j][i]))).collect();
                        s[enc(&w)] = true;
                    }
                }
                span[t] = s;
            }
            // minimum distance d: smallest |T| whose columns are dependent
            let mut dmin = n_len + 1;
            for &t in &subsets {
                let sz = t.count_ones() as usize;
                let dim_full = (p as usize).pow(sz as u32);
                if t != 0 && span[t].iter().filter(|&&b| b).count() < dim_full {
                    dmin = dmin.min(sz);
                }
            }
            // single coset leader weights
            let mut wt = vec![usize::MAX; nsyn];
            for &t in &subsets {
                let sz = t.count_ones() as usize;
                for (idx, &b) in span[t].iter().enumerate() {
                    if b && wt[idx] > sz {
                        wt[idx] = sz;
                    }
                }
            }
            // precompute syndrome vectors
            let svec: Vec<Vec<u64>> = (0..nsyn).map(dec).collect();
            let tmax = (dmin - 1) / 2; // largest t < d/2
            // best[t][e] = max #close z over pairs with interleaved distance e
            let mut best = vec![vec![0usize; n_len + 1]; tmax + 1];
            let mut witness = vec![vec![(0usize, 0usize); n_len + 1]; tmax + 1];
            for sa in 0..nsyn {
                for sb in 0..nsyn {
                    let mut lw = [0usize; 64];
                    let (va, vb) = (&svec[sa], &svec[sb]);
                    for z in 0..p {
                        let w: Vec<u64> = (0..r).map(|i| f.add(va[i], f.mul(z, vb[i]))).collect();
                        lw[z as usize] = wt[enc(&w)];
                    }
                    // only pairs with >= 3 close z at the largest budget are interesting
                    if (0..p as usize).filter(|&z| lw[z] <= tmax).count() < 3 {
                        continue;
                    }
                    // interleaved distance
                    let mut e = n_len;
                    for &t in &subsets {
                        let sz = t.count_ones() as usize;
                        if sz >= e {
                            break;
                        }
                        if span[t][sa] && span[t][sb] {
                            e = sz;
                            break;
                        }
                    }
                    for t in 0..=tmax {
                        let cnt = (0..p as usize).filter(|&z| lw[z] <= t).count();
                        if cnt > best[t][e] {
                            best[t][e] = cnt;
                            witness[t][e] = (sa, sb);
                        }
                    }
                }
            }
            println!(
                "\ncode q={p} N={n_len} k={kdim} (trial {trial}): d = {dmin}, Delta/3 = {:.2}, Delta/2 = {:.2} (in positions)",
                dmin as f64 / 3.0,
                dmin as f64 / 2.0
            );
            for t in 0..=tmax {
                let regime = if (t as f64) < dmin as f64 / 3.0 {
                    "t < d/3"
                } else {
                    "d/3 <= t < d/2"
                };
                let row: Vec<String> = ((t + 1)..=n_len)
                    .map(|e| format!("e*={e}:{}", best[t][e]))
                    .collect();
                println!(
                    "  t={t} [{regime}]  max #close z (out of {p}) with interleaved distance e* > t: {}",
                    row.join("  ")
                );
            }
        }
    }
}

// every r columns of H independent  <=>  code is MDS (d = r + 1)
fn is_mds(f: &Fp, cols: &[Vec<u64>], r: usize) -> bool {
    let n = cols.len();
    let mut idx: Vec<usize> = (0..r).collect();
    loop {
        let mut m: Vec<Vec<u64>> = (0..r)
            .map(|i| idx.iter().map(|&c| cols[c][i]).collect())
            .collect();
        if rref(f, &mut m, r).0 < r {
            return false;
        }
        let mut i = r;
        loop {
            if i == 0 {
                return true;
            }
            i -= 1;
            if idx[i] < n - r + i {
                break;
            }
        }
        idx[i] += 1;
        for j in i + 1..r {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

// Check of the "generic uniform matroid" claim: over a large field with random per-node gates,
// EVERY D-subset of positions is nonsingular (exhaustive for small n, k).
pub fn exp_mds_exhaustive() {
    let f = Fp {
        p: 0xFFFF_FFFF_0000_0001,
    };
    let mut rng = Rng(99);
    for &(n, k) in &[(2usize, 1usize), (2, 2), (2, 3), (3, 1), (3, 2)] {
        let d = 1usize << n;
        let len = 1usize << (n + k);
        let gates = sample_gates(&f, n, k, Mode::PerNode, &mut rng);
        let cols: Vec<Vec<u64>> = (0..len).map(|p| column(&f, n, p, &gates)).collect();
        let mut idx: Vec<usize> = (0..d).collect();
        let (mut total, mut singular) = (0u64, 0u64);
        loop {
            let mut m: Vec<Vec<u64>> = idx.iter().map(|&x| cols[x].clone()).collect();
            if rref(&f, &mut m, d).0 < d {
                singular += 1;
            }
            total += 1;
            let mut i = d;
            loop {
                if i == 0 {
                    break;
                }
                i -= 1;
                if idx[i] < len - d + i {
                    break;
                }
                if i == 0 {
                    i = usize::MAX;
                    break;
                }
            }
            if i == usize::MAX || (i == 0 && idx[0] >= len - d) {
                break;
            }
            idx[i] += 1;
            for j in i + 1..d {
                idx[j] = idx[j - 1] + 1;
            }
        }
        println!(
            "Goldilocks n={n} k={k}: {total} subsets of size {d} out of {len}, singular: {singular}"
        );
    }
}

// Check of the collision obstruction: one level-1 collision t^0(b) = t^0(b') yields
// a codeword of C_n with >= 3*2^(n-1) - 1 zeros (MDS would allow at most 2^n - 1).
pub fn exp_collision() {
    let f = Fp {
        p: (1u64 << 31) - 1,
    };
    let mut rng = Rng(5150);
    for &(n, k) in &[(3usize, 1usize), (5, 2), (8, 2), (10, 3)] {
        let mut gates = sample_gates(&f, n, k, Mode::PerNode, &mut rng);
        // force the collision at level 1 (gates[0], nodes beta = 0 and 1)
        let a = gates[0].0[0];
        gates[0].0[1] = a;
        if gates[0].1[1] == a {
            gates[0].1[1] = f.add(a, 1);
        }
        // F_1 = x - a  (level-1 variable)
        let mut fpoly: Vec<u64> = vec![f.sub(0, a), 1];
        for j in 2..=n {
            let enc_prev = encode(&f, &fpoly, k, &gates);
            let p = enc_prev.iter().position(|&x| x != 0).unwrap();
            let aj = gates[j - 1].0[p]; // structural point t^0 at node p of level j
            let mut next = vec![0u64; fpoly.len() * 2];
            for (m, &c) in fpoly.iter().enumerate() {
                next[2 * m] = f.sub(0, f.mul(aj, c));
                next[2 * m + 1] = c;
            }
            fpoly = next;
        }
        let cw = encode(&f, &fpoly, k, &gates);
        let zeros = cw.iter().filter(|&&x| x == 0).count();
        let l = cw.len();
        println!(
            "n={n:>2} k={k}: zeros = {zeros} (claim >= {}, MDS max {}), relative weight {:.4} vs 1-3R/2+1/L = {:.4}",
            3 * (1usize << (n - 1)) - 1,
            (1usize << n) - 1,
            1.0 - zeros as f64 / l as f64,
            1.0 - 1.5 / (1u64 << k) as f64 + 1.0 / l as f64
        );
    }
}

// Theorem 3.14 started from a checked level i0 (C_{i0} verified MDS at setup: Z_{i0} = D_{i0}).
fn distance_bound_v2_from(log2q: f64, n: usize, k: usize, lambda: f64, i0: usize) -> f64 {
    let target = -(lambda + (n as f64).log2());
    let mut z_prev = 2f64.powi(i0 as i32); // Z_{i0} = D_{i0}
    for i in (i0 + 1)..=n {
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

pub fn checked_setup_table() {
    println!("Thm 3.14 with the lowest levels verified MDS at setup (n = 20, lambda = 128)");
    println!(
        "{:>12} {:>3} {:>8} {:>8} {:>8} {:>8}",
        "gate field", "k", "i0=0", "i0=1", "i0=2", "i0=3"
    );
    for &(name, lq) in &[("M31", 31.0f64), ("Goldilocks", 64.0), ("GL^3", 192.0)] {
        for k in 2..=6usize {
            let v: Vec<String> = (0..=3)
                .map(|i0| {
                    let d = distance_bound_v2_from(lq, 20, k, 128.0, i0);
                    if d.is_nan() || d <= 0.0 {
                        "-".into()
                    } else {
                        format!("{d:.3}")
                    }
                })
                .collect();
            println!(
                "{:>12} {:>3} {:>8} {:>8} {:>8} {:>8}",
                name, k, v[0], v[1], v[2], v[3]
            );
        }
    }
}

// Check of the Brief-3 counterexample: U = Vandermonde (r x 2r), t_p = x_p^(r-f).
// Claim: rank [U; U diag(t)] = 2r - f, and every set of <= 2r - f columns is independent.
pub fn exp_vandermonde_circuit() {
    let f = Fp {
        p: (1u64 << 31) - 1,
    };
    for &(r, ff) in &[(2usize, 1usize), (3, 1), (4, 1), (4, 2), (5, 3), (6, 1)] {
        let m = 2 * r;
        let xs: Vec<u64> = (0..m).map(|i| (i as u64) * 7 + 3).collect();
        // columns c_p = (x^0..x^{r-1}, t x^0..t x^{r-1})
        let cols: Vec<Vec<u64>> = xs
            .iter()
            .map(|&x| {
                let t = f.pow(x, (r - ff) as u64);
                let mut c: Vec<u64> = (0..r).map(|i| f.pow(x, i as u64)).collect();
                let lower: Vec<u64> = (0..r).map(|i| f.mul(t, f.pow(x, i as u64))).collect();
                c.extend(lower);
                c
            })
            .collect();
        let mut all: Vec<Vec<u64>> = cols.clone();
        let rank = rref(&f, &mut all, 2 * r).0;
        // every (2r - f)-subset of columns independent
        let s = m - ff;
        let mut ok = true;
        let mut idx: Vec<usize> = (0..s).collect();
        loop {
            let mut sub: Vec<Vec<u64>> = idx.iter().map(|&i| cols[i].clone()).collect();
            if rref(&f, &mut sub, 2 * r).0 < s {
                ok = false;
                break;
            }
            let mut i = s;
            let mut done = true;
            while i > 0 {
                i -= 1;
                if idx[i] < m - s + i {
                    done = false;
                    break;
                }
            }
            if done {
                break;
            }
            idx[i] += 1;
            for j in i + 1..s {
                idx[j] = idx[j - 1] + 1;
            }
        }
        println!(
            "r={r} f={ff}: rank = {rank} (claim {}), all {}-subsets independent: {ok}",
            2 * r - ff,
            s
        );
    }
}

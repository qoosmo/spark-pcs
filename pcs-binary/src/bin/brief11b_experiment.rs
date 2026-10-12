#![allow(
// SPDX-License-Identifier: MIT OR Apache-2.0
    dead_code,
    non_snake_case,
    unused_mut,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashSet;

fn add(a: u32, b: u32, q: u32) -> u32 {
    let x = a + b;
    if x >= q {
        x - q
    } else {
        x
    }
}
fn sub(a: u32, b: u32, q: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + q - b
    }
}
fn mul(a: u32, b: u32, q: u32) -> u32 {
    ((a as u64 * b as u64) % q as u64) as u32
}
fn pow(mut a: u32, mut e: u32, q: u32) -> u32 {
    let mut r = 1;
    while e > 0 {
        if e & 1 == 1 {
            r = mul(r, a, q);
        }
        a = mul(a, a, q);
        e >>= 1;
    }
    r
}
fn inv(a: u32, q: u32) -> u32 {
    assert!(a != 0);
    pow(a, q - 2, q)
}

fn rank(mut a: Vec<Vec<u32>>, q: u32) -> usize {
    if a.is_empty() {
        return 0;
    }
    let rows = a.len();
    let cols = a[0].len();
    let mut r = 0;
    for c in 0..cols {
        let mut p = r;
        while p < rows && a[p][c] == 0 {
            p += 1
        }
        if p == rows {
            continue;
        }
        a.swap(r, p);
        let iv = inv(a[r][c], q);
        for j in c..cols {
            a[r][j] = mul(a[r][j], iv, q);
        }
        for i in 0..rows {
            if i == r {
                continue;
            }
            let f = a[i][c];
            if f != 0 {
                for j in c..cols {
                    a[i][j] = sub(a[i][j], mul(f, a[r][j], q), q);
                }
            }
        }
        r += 1;
        if r == rows {
            break;
        }
    }
    r
}

fn null_vector_rank_dminus1(
    cols: &[Vec<u32>],
    idx: &[usize],
    d: usize,
    q: u32,
) -> Option<Vec<u32>> {
    // equations: selected column_j dot m = 0
    let mut a = vec![vec![0u32; d]; d - 1];
    for (i, &p) in idx.iter().enumerate() {
        for j in 0..d {
            a[i][j] = cols[p][j];
        }
    }
    let mut row = 0usize;
    let mut piv = vec![None; d];
    for c in 0..d {
        let mut p = row;
        while p < d - 1 && a[p][c] == 0 {
            p += 1
        }
        if p == d - 1 {
            continue;
        }
        a.swap(row, p);
        let iv = inv(a[row][c], q);
        for j in c..d {
            a[row][j] = mul(a[row][j], iv, q);
        }
        for i in 0..d - 1 {
            if i == row {
                continue;
            }
            let f = a[i][c];
            if f != 0 {
                for j in c..d {
                    a[i][j] = sub(a[i][j], mul(f, a[row][j], q), q);
                }
            }
        }
        piv[c] = Some(row);
        row += 1;
        if row == d - 1 {
            break;
        }
    }
    if row != d - 1 {
        return None;
    }
    let free = (0..d).find(|&c| piv[c].is_none()).unwrap();
    let mut m = vec![0u32; d];
    m[free] = 1;
    for c in (0..d).rev() {
        if let Some(r) = piv[c] {
            let mut s = 0;
            for j in c + 1..d {
                s = add(s, mul(a[r][j], m[j], q), q);
            }
            m[c] = sub(0, s, q);
        }
    }
    Some(m)
}

fn combinations(n: usize, k: usize, mut f: impl FnMut(&[usize])) {
    fn rec(n: usize, k: usize, start: usize, cur: &mut Vec<usize>, f: &mut dyn FnMut(&[usize])) {
        if cur.len() == k {
            f(cur);
            return;
        }
        let need = k - cur.len();
        for x in start..=n - need {
            cur.push(x);
            rec(n, k, x + 1, cur, f);
            cur.pop();
        }
    }
    let mut cur = Vec::with_capacity(k);
    rec(n, k, 0, &mut cur, &mut f);
}

fn exact_distance(g: &[Vec<u32>], q: u32) -> usize {
    let d = g.len();
    let l = g[0].len();
    let cols = (0..l)
        .map(|p| (0..d).map(|r| g[r][p]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut max_zero = 0usize;
    combinations(l, d - 1, |idx| {
        if let Some(m) = null_vector_rank_dminus1(&cols, idx, d, q) {
            let z = cols
                .iter()
                .filter(|c| {
                    let mut s = 0;
                    for j in 0..d {
                        s = add(s, mul(m[j], c[j], q), q);
                    }
                    s == 0
                })
                .count();
            if z > max_zero {
                max_zero = z;
            }
        }
    });
    l - max_zero
}

fn random_full_rank_generator(d: usize, l: usize, q: u32, rng: &mut StdRng) -> Vec<Vec<u32>> {
    loop {
        let g = (0..d)
            .map(|_| (0..l).map(|_| rng.gen_range(0..q)).collect())
            .collect::<Vec<Vec<u32>>>();
        if rank(g.clone(), q) == d {
            return g;
        }
    }
}

fn spark_generator(n: usize, k: usize, q: u32, rng: &mut StdRng) -> Vec<Vec<u32>> {
    let d = 1usize << n;
    let copies = 1usize << k;
    let l = d * copies;
    let mut levels = Vec::new();
    for i in 0..n {
        let parents = 1usize << (k + i);
        let mut gs = Vec::with_capacity(parents);
        for _ in 0..parents {
            let t0 = rng.gen_range(0..q);
            let mut t1 = rng.gen_range(0..q);
            while t1 == t0 {
                t1 = rng.gen_range(0..q);
            }
            gs.push((t0, t1));
        }
        levels.push(gs);
    }
    let mut G = vec![vec![0u32; l]; d];
    for basis in 0..d {
        let mut src = vec![0u32; l];
        for coeff in 0..d {
            let v = if coeff == basis { 1 } else { 0 };
            for j in 0..copies {
                src[coeff * copies + j] = v;
            }
        }
        let mut dst = vec![0u32; l];
        for (i, lev) in levels.iter().enumerate() {
            let parents = 1usize << (k + i);
            let pair_span = 2 * parents;
            for out_pair in 0..l / 2 {
                let block_pair = out_pair / parents;
                let p = out_pair % parents;
                let base = block_pair * pair_span;
                let u = src[base + p];
                let v = src[base + parents + p];
                let (t0, t1) = lev[p];
                dst[2 * out_pair] = add(u, mul(t0, v, q), q);
                dst[2 * out_pair + 1] = add(u, mul(t1, v, q), q);
            }
            std::mem::swap(&mut src, &mut dst);
        }
        G[basis] = src;
    }
    G
}

fn encode_msg(g: &[Vec<u32>], m: &[u32], q: u32) -> Vec<u32> {
    let l = g[0].len();
    let d = g.len();
    let mut w = vec![0; l];
    for p in 0..l {
        let mut s = 0;
        for j in 0..d {
            s = add(s, mul(m[j], g[j][p], q), q);
        }
        w[p] = s;
    }
    w
}

fn invert_square(mut a: Vec<Vec<u32>>, q: u32) -> Option<Vec<Vec<u32>>> {
    let n = a.len();
    let mut aug = vec![vec![0u32; 2 * n]; n];
    for i in 0..n {
        for j in 0..n {
            aug[i][j] = a[i][j];
        }
        aug[i][n + i] = 1;
    }
    for c in 0..n {
        let mut p = c;
        while p < n && aug[p][c] == 0 {
            p += 1
        }
        if p == n {
            return None;
        }
        aug.swap(c, p);
        let iv = inv(aug[c][c], q);
        for j in c..2 * n {
            aug[c][j] = mul(aug[c][j], iv, q);
        }
        for i in 0..n {
            if i != c {
                let f = aug[i][c];
                if f != 0 {
                    for j in c..2 * n {
                        aug[i][j] = sub(aug[i][j], mul(f, aug[c][j], q), q);
                    }
                }
            }
        }
    }
    Some((0..n).map(|i| aug[i][n..].to_vec()).collect())
}

#[derive(Clone)]
struct InfoSet {
    pos: Vec<usize>,
    inv: Vec<Vec<u32>>,
}

fn info_sets(g: &[Vec<u32>], q: u32, rng: &mut StdRng, count: usize) -> Vec<InfoSet> {
    let d = g.len();
    let l = g[0].len();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut tries = 0;
    while out.len() < count && tries < count * 100 {
        tries += 1;
        let mut pos = Vec::new();
        while pos.len() < d {
            let x = rng.gen_range(0..l);
            if !pos.contains(&x) {
                pos.push(x);
            }
        }
        pos.sort_unstable();
        if !seen.insert(pos.clone()) {
            continue;
        }
        let a = (0..d)
            .map(|i| (0..d).map(|j| g[j][pos[i]]).collect())
            .collect::<Vec<Vec<u32>>>();
        if let Some(iv) = invert_square(a, q) {
            out.push(InfoSet { pos, inv: iv });
        }
    }
    out
}

fn decode(y: &[u32], g: &[Vec<u32>], sets: &[InfoSet], t: usize, q: u32) -> Option<Vec<u32>> {
    let d = g.len();
    for s in sets {
        let rhs = s.pos.iter().map(|&p| y[p]).collect::<Vec<_>>();
        let mut m = vec![0u32; d];
        for i in 0..d {
            let mut z = 0;
            for j in 0..d {
                z = add(z, mul(s.inv[i][j], rhs[j], q), q);
            }
            m[i] = z;
        }
        let c = encode_msg(g, &m, q);
        let dist = c.iter().zip(y).filter(|(a, b)| a != b).count();
        if dist <= t {
            return Some(m);
        }
    }
    None
}

fn line_stats(decoded: &[(u32, Vec<u32>)], q: u32) -> (usize, Option<(Vec<u32>, Vec<u32>)>) {
    if decoded.len() < 2 {
        return (decoded.len(), None);
    }
    let d = decoded[0].1.len();
    let mut best = 0;
    let mut bestline = None;
    for i in 0..decoded.len() {
        for j in i + 1..decoded.len() {
            let (r1, m1) = &decoded[i];
            let (r2, m2) = &decoded[j];
            let den = inv(sub(*r2, *r1, q), q);
            let mut b = vec![0; d];
            let mut a = vec![0; d];
            for x in 0..d {
                b[x] = mul(sub(m2[x], m1[x], q), den, q);
                a[x] = sub(m1[x], mul(*r1, b[x], q), q);
            }
            let cnt = decoded
                .iter()
                .filter(|(r, m)| (0..d).all(|x| m[x] == add(a[x], mul(*r, b[x], q), q)))
                .count();
            if cnt > best {
                best = cnt;
                bestline = Some((a, b));
            }
        }
    }
    (best, bestline)
}

fn eval_pair(
    A: &[u32],
    B: &[u32],
    g: &[Vec<u32>],
    sets: &[InfoSet],
    t: usize,
    q: u32,
    mabs: usize,
) -> (usize, usize, usize, usize) {
    let l = A.len();
    let mut dec = Vec::new();
    for r in 0..q {
        let y = (0..l)
            .map(|p| add(A[p], mul(r, B[p], q), q))
            .collect::<Vec<_>>();
        if let Some(m) = decode(&y, g, sets, t, q) {
            dec.push((r, m));
        }
    }
    let (mc, line) = line_stats(&dec, q);
    let mut off = dec.len().saturating_sub(mc);
    let mut bad10 = off;
    if let Some((a, b)) = line {
        let ca = encode_msg(g, &a, q);
        let cb = encode_msg(g, &b, q);
        let e = (0..l)
            .map(|p| A[p] != ca[p] || B[p] != cb[p])
            .collect::<Vec<_>>();
        for (r, m) in dec.iter() {
            if !(0..m.len()).all(|x| m[x] == add(a[x], mul(*r, b[x], q), q)) {
                continue;
            }
            let c = encode_msg(g, m, q);
            let y = (0..l)
                .map(|p| add(A[p], mul(*r, B[p], q), q))
                .collect::<Vec<_>>();
            let extra = (0..l).filter(|&p| e[p] && y[p] == c[p]).count();
            if extra as f64 > 0.10 * l as f64 {
                bad10 += 1;
            }
        }
    }
    let noheavy = if mc < mabs { dec.len() } else { 0 };
    (dec.len(), mc, off, bad10.max(noheavy))
}

fn random_word(l: usize, q: u32, rng: &mut StdRng) -> Vec<u32> {
    (0..l).map(|_| rng.gen_range(0..q)).collect()
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let seeds = args
        .iter()
        .position(|x| x == "--seeds")
        .and_then(|i| args.get(i + 1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(2usize);
    let iters = args
        .iter()
        .position(|x| x == "--iters")
        .and_then(|i| args.get(i + 1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(1500usize);
    let infos = args
        .iter()
        .position(|x| x == "--infos")
        .and_then(|i| args.get(i + 1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(512usize);

    println!("kind,q,n,k,L,D,d,Delta,triple,t,delta,Mabs,seed,best_noheavy_close,best_max_collinear,best_bad_eps10");
    for &q in &[13u32, 17, 31] {
        for &n in &[2usize, 3] {
            for &k in &[1usize, 2] {
                let d = 1usize << n;
                let l = 1usize << (n + k);
                for seed in 0..seeds {
                    for kind in ["spark", "random"] {
                        let mut rng = StdRng::seed_from_u64(
                            0xB11B0000u64
                                ^ ((q as u64) << 32)
                                ^ ((n as u64) << 24)
                                ^ ((k as u64) << 16)
                                ^ seed as u64
                                ^ if kind == "random" { 0x9999 } else { 0 },
                        );
                        let g = if kind == "spark" {
                            spark_generator(n, k, q, &mut rng)
                        } else {
                            random_full_rank_generator(d, l, q, &mut rng)
                        };
                        let dist = exact_distance(&g, q);
                        let delta_code = dist as f64 / l as f64;
                        let triple = 1.0 - (1.0 - delta_code).cbrt();
                        let t = (dist.saturating_sub(1)) / 2;
                        let delta = t as f64 / l as f64;
                        if !(delta > triple && 2 * t < dist) {
                            println!("{kind},{q},{n},{k},{l},{d},{dist},{delta_code:.6},{triple:.6},{t},{delta:.6},0,{seed},SKIP_NO_INTEGER_RADIUS,0,0");
                            continue;
                        }
                        let mabs = t / (dist - 2 * t) + 2;
                        let sets = info_sets(&g, q, &mut rng, infos);

                        let mut best_noheavy = 0usize;
                        let mut best_mc = 0usize;
                        let mut best_bad = 0usize;
                        // random search
                        for _ in 0..iters {
                            let a = random_word(l, q, &mut rng);
                            let b = random_word(l, q, &mut rng);
                            let (close, mc, _, bad) = eval_pair(&a, &b, &g, &sets, t, q, mabs);
                            if mc < mabs && close > best_noheavy {
                                best_noheavy = close
                            }
                            best_mc = best_mc.max(mc);
                            best_bad = best_bad.max(bad);
                        }

                        // adversarial hill-climb start near one valid code-line
                        let ma = (0..d).map(|_| rng.gen_range(0..q)).collect::<Vec<_>>();
                        let mb = (0..d).map(|_| rng.gen_range(0..q)).collect::<Vec<_>>();
                        let mut a = encode_msg(&g, &ma, q);
                        let mut b = encode_msg(&g, &mb, q);
                        for _ in 0..t {
                            let p = rng.gen_range(0..l);
                            a[p] = rng.gen_range(0..q);
                        }
                        for _ in 0..t {
                            let p = rng.gen_range(0..l);
                            b[p] = rng.gen_range(0..q);
                        }
                        let mut cur = eval_pair(&a, &b, &g, &sets, t, q, mabs);
                        for _ in 0..iters {
                            let mut na = a.clone();
                            let mut nb = b.clone();
                            if rng.gen_bool(0.5) {
                                let p = rng.gen_range(0..l);
                                na[p] = rng.gen_range(0..q);
                            } else {
                                let p = rng.gen_range(0..l);
                                nb[p] = rng.gen_range(0..q);
                            }
                            let nxt = eval_pair(&na, &nb, &g, &sets, t, q, mabs);
                            let score = |x: (usize, usize, usize, usize)| -> isize {
                                let noheavy = if x.1 < mabs { x.0 as isize } else { 0 };
                                1000 * noheavy + 10 * x.3 as isize + x.0 as isize
                            };
                            if score(nxt) >= score(cur) {
                                a = na;
                                b = nb;
                                cur = nxt;
                            }
                            if cur.1 < mabs {
                                best_noheavy = best_noheavy.max(cur.0);
                            }
                            best_mc = best_mc.max(cur.1);
                            best_bad = best_bad.max(cur.3);
                        }

                        println!("{kind},{q},{n},{k},{l},{d},{dist},{delta_code:.6},{triple:.6},{t},{delta:.6},{mabs},{seed},{best_noheavy},{best_mc},{best_bad}");
                    }
                }
            }
        }
    }
    eprintln!("NOTE: decoding uses randomized information sets; a found counterexample is actionable, but absence of one is empirical evidence only.");
}

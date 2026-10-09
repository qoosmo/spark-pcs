#![allow(dead_code, unused_imports, unused_mut, clippy::needless_range_loop)]

// Brief 13c: final Part D experiment.
// Rust only; no external crates; no core protocol changes.
//
// Exact list decoding uses a covering family of invertible information sets.
// Exact lifting uses linear consistency on Agr after deleting at most epsL
// positions (epsL in {0,1,2}).
//
// Defaults:
//   5 SPARK families + 5 random controls per case
//   1000 scored word trials per code/radius
//
// Usage:
//   cargo run --release --bin brief13c_partd -- [trials]
// Optional L=32 case:
//   BRIEF13C_OPTIONAL=1 cargo run --release --bin brief13c_partd -- [trials]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug)]
struct GF {
    m: u32,
    poly: u16,
    q: u16,
    name: &'static str,
}
impl GF {
    #[inline]
    fn add(self, a: u16, b: u16) -> u16 {
        a ^ b
    }
    #[inline]
    fn mul(self, mut a: u16, mut b: u16) -> u16 {
        let mut r = 0u16;
        let top = 1u16 << self.m;
        let mask = self.q - 1;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a & top != 0 {
                a ^= self.poly;
            }
            a &= mask;
        }
        r & mask
    }
    fn pow(self, mut a: u16, mut e: u32) -> u16 {
        let mut r = 1u16;
        while e > 0 {
            if e & 1 != 0 {
                r = self.mul(r, a);
            }
            a = self.mul(a, a);
            e >>= 1;
        }
        r
    }
    fn inv(self, a: u16) -> u16 {
        assert!(a != 0);
        self.pow(a, self.q as u32 - 2)
    }
}

#[derive(Clone)]
struct Rng64 {
    s: u64,
}
impl Rng64 {
    fn new(s: u64) -> Self {
        Self { s: s.max(1) }
    }
    fn next(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.s = x;
        x
    }
    fn elt(&mut self, f: GF) -> u16 {
        (self.next() % (f.q as u64)) as u16
    }
    fn usize(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

#[derive(Clone, Debug)]
struct Code {
    field: GF,
    n: usize,
    k: usize,
    l: usize,
    d: usize,
    gen: Vec<u16>, // L x D rows
    label: String,
    seed: u64,
    gates: Option<Vec<Vec<(u16, u16)>>>,
}

fn rank(mut a: Vec<Vec<u16>>, f: GF) -> usize {
    if a.is_empty() {
        return 0;
    }
    let nr = a.len();
    let nc = a[0].len();
    let mut r = 0;
    for c in 0..nc {
        let mut p = r;
        while p < nr && a[p][c] == 0 {
            p += 1
        }
        if p == nr {
            continue;
        }
        a.swap(r, p);
        let inv = f.inv(a[r][c]);
        for j in c..nc {
            a[r][j] = f.mul(a[r][j], inv);
        }
        for i in 0..nr {
            if i == r || a[i][c] == 0 {
                continue;
            }
            let z = a[i][c];
            for j in c..nc {
                a[i][j] = f.add(a[i][j], f.mul(z, a[r][j]));
            }
        }
        r += 1;
        if r == nr {
            break;
        }
    }
    r
}

fn solve_full_rank(rows: &[Vec<u16>], rhs: &[u16], d: usize, f: GF) -> Option<Vec<u16>> {
    if rows.len() != rhs.len() {
        return None;
    }
    let mut a = Vec::with_capacity(rows.len());
    for (r, &y) in rows.iter().zip(rhs) {
        let mut z = r.clone();
        z.push(y);
        a.push(z);
    }
    let nr = a.len();
    let mut piv = 0usize;
    let mut pivcol = Vec::new();
    for c in 0..d {
        let mut p = piv;
        while p < nr && a[p][c] == 0 {
            p += 1
        }
        if p == nr {
            continue;
        }
        a.swap(piv, p);
        let inv = f.inv(a[piv][c]);
        for j in c..=d {
            a[piv][j] = f.mul(a[piv][j], inv);
        }
        for i in 0..nr {
            if i == piv || a[i][c] == 0 {
                continue;
            }
            let z = a[i][c];
            for j in c..=d {
                a[i][j] = f.add(a[i][j], f.mul(z, a[piv][j]));
            }
        }
        pivcol.push(c);
        piv += 1;
        if piv == nr {
            break;
        }
    }
    for i in 0..nr {
        if a[i][..d].iter().all(|&x| x == 0) && a[i][d] != 0 {
            return None;
        }
    }
    if piv < d {
        return None;
    } // unique solution required here
    let mut x = vec![0u16; d];
    for i in 0..d {
        x[pivcol[i]] = a[i][d];
    }
    Some(x)
}

fn consistent(rows: &[Vec<u16>], rhs: &[u16], d: usize, f: GF) -> bool {
    if rows.is_empty() {
        return true;
    }
    let mut a = Vec::with_capacity(rows.len());
    for (r, &y) in rows.iter().zip(rhs) {
        let mut z = r.clone();
        z.push(y);
        a.push(z);
    }
    let nr = a.len();
    let mut piv = 0usize;
    for c in 0..d {
        let mut p = piv;
        while p < nr && a[p][c] == 0 {
            p += 1
        }
        if p == nr {
            continue;
        }
        a.swap(piv, p);
        let inv = f.inv(a[piv][c]);
        for j in c..=d {
            a[piv][j] = f.mul(a[piv][j], inv);
        }
        for i in 0..nr {
            if i == piv || a[i][c] == 0 {
                continue;
            }
            let z = a[i][c];
            for j in c..=d {
                a[i][j] = f.add(a[i][j], f.mul(z, a[piv][j]));
            }
        }
        piv += 1;
        if piv == nr {
            break;
        }
    }
    for i in 0..nr {
        if a[i][..d].iter().all(|&x| x == 0) && a[i][d] != 0 {
            return false;
        }
    }
    true
}

fn spark_code(n: usize, k: usize, f: GF, seed: u64) -> Code {
    let mut rng = Rng64::new(seed);
    let mut gates = Vec::new();
    for level in 0..n {
        let cnt = 1usize << (k + level);
        let mut gl = Vec::new();
        for _ in 0..cnt {
            let a = rng.elt(f);
            let mut b = rng.elt(f);
            while b == a {
                b = rng.elt(f);
            }
            gl.push((a, b));
        }
        gates.push(gl);
    }
    let l = 1usize << (n + k);
    let d = 1usize << n;
    let mut gen = vec![0u16; l * d];
    for pos in 0..l {
        let beta = pos >> n;
        let mut prefix = beta;
        let mut ys = vec![0u16; n];
        for level in 0..n {
            let bit = (pos >> (n - 1 - level)) & 1;
            let pair = gates[level][prefix];
            ys[level] = if bit == 0 { pair.0 } else { pair.1 };
            prefix = (prefix << 1) | bit;
        }
        for mask in 0..d {
            let mut v = 1u16;
            for j in 0..n {
                if (mask >> (n - 1 - j)) & 1 != 0 {
                    v = f.mul(v, ys[j]);
                }
            }
            gen[pos * d + mask] = v;
        }
    }
    Code {
        field: f,
        n,
        k,
        l,
        d,
        gen,
        label: "spark".into(),
        seed,
        gates: Some(gates),
    }
}

fn random_code(l: usize, d: usize, f: GF, seed: u64) -> Code {
    let mut rng = Rng64::new(seed);
    loop {
        let mut gen = vec![0u16; l * d];
        for x in &mut gen {
            *x = rng.elt(f);
        }
        let rows = (0..l)
            .map(|i| gen[i * d..(i + 1) * d].to_vec())
            .collect::<Vec<_>>();
        if rank(rows, f) == d {
            return Code {
                field: f,
                n: d.trailing_zeros() as usize,
                k: 0,
                l,
                d,
                gen,
                label: "random".into(),
                seed,
                gates: None,
            };
        }
    }
}

#[inline]
fn grow_index(mut x: u64, d: usize, q: u16) -> Vec<u16> {
    let mut m = vec![0u16; d];
    for i in 0..d {
        m[i] = (x % (q as u64)) as u16;
        x /= q as u64;
    }
    m
}
#[inline]
fn msg_index(m: &[u16], q: u16) -> u64 {
    let mut z = 0u64;
    let mut p = 1u64;
    for &x in m {
        z += (x as u64) * p;
        p *= q as u64;
    }
    z
}
fn encode_msg(c: &Code, m: &[u16]) -> Vec<u16> {
    let f = c.field;
    (0..c.l)
        .map(|p| {
            let mut s = 0;
            for j in 0..c.d {
                s = f.add(s, f.mul(c.gen[p * c.d + j], m[j]));
            }
            s
        })
        .collect()
}
fn random_codeword(c: &Code, rng: &mut Rng64) -> (Vec<u16>, Vec<u16>) {
    let m = (0..c.d).map(|_| rng.elt(c.field)).collect::<Vec<_>>();
    let w = encode_msg(c, &m);
    (m, w)
}

fn exact_distance(c: &Code) -> usize {
    // Enumerate projective message representatives: first nonzero entry = 1.
    let q = c.field.q as u64;
    let mut best = c.l + 1;
    for first in 0..c.d {
        let suffix = c.d - first - 1;
        let total = q.pow(suffix as u32);
        for z0 in 0..total {
            let mut m = vec![0u16; c.d];
            m[first] = 1;
            let mut z = z0;
            for j in first + 1..c.d {
                m[j] = (z % q) as u16;
                z /= q;
            }
            let w = encode_msg(c, &m);
            let wt = w.iter().filter(|&&x| x != 0).count();
            if wt < best {
                best = wt;
            }
        }
    }
    best
}

fn comb_masks(l: usize, w: usize) -> Vec<u32> {
    if w == 0 {
        return vec![0];
    }
    let mut out = Vec::new();
    fn rec(start: usize, left: usize, l: usize, mask: u32, out: &mut Vec<u32>) {
        if left == 0 {
            out.push(mask);
            return;
        }
        for i in start..=l - left {
            rec(i + 1, left - 1, l, mask | (1u32 << i), out);
        }
    }
    rec(0, w, l, 0, &mut out);
    out
}
fn positions(mask: u32, l: usize) -> Vec<usize> {
    (0..l).filter(|&i| mask & (1u32 << i) != 0).collect()
}

#[derive(Clone)]
struct InfoSet {
    pos: Vec<usize>,
    inv: Vec<Vec<u16>>,
}

fn invert_square(mut a: Vec<Vec<u16>>, f: GF) -> Option<Vec<Vec<u16>>> {
    let d = a.len();
    let mut aug = vec![vec![0u16; 2 * d]; d];
    for i in 0..d {
        for j in 0..d {
            aug[i][j] = a[i][j];
        }
        aug[i][d + i] = 1;
    }
    for c in 0..d {
        let mut p = c;
        while p < d && aug[p][c] == 0 {
            p += 1
        }
        if p == d {
            return None;
        }
        aug.swap(c, p);
        let inv = f.inv(aug[c][c]);
        for j in c..2 * d {
            aug[c][j] = f.mul(aug[c][j], inv);
        }
        for i in 0..d {
            if i == c || aug[i][c] == 0 {
                continue;
            }
            let z = aug[i][c];
            for j in c..2 * d {
                aug[i][j] = f.add(aug[i][j], f.mul(z, aug[c][j]));
            }
        }
    }
    Some((0..d).map(|i| aug[i][d..].to_vec()).collect())
}

fn info_cover(c: &Code, e: usize) -> Vec<InfoSet> {
    assert!(c.l <= 32);
    let all_info = comb_masks(c.l, c.d)
        .into_iter()
        .filter_map(|mask| {
            let pos = positions(mask, c.l);
            let mat = pos
                .iter()
                .map(|&p| c.gen[p * c.d..(p + 1) * c.d].to_vec())
                .collect::<Vec<_>>();
            invert_square(mat, c.field).map(|inv| (mask, InfoSet { pos, inv }))
        })
        .collect::<Vec<_>>();
    let mut uncovered = comb_masks(c.l, e);
    let mut chosen = Vec::new();
    while !uncovered.is_empty() {
        let mut best_i = 0usize;
        let mut best_n = 0usize;
        for (i, (mask, _)) in all_info.iter().enumerate() {
            let n = uncovered.iter().filter(|&&em| em & *mask == 0).count();
            if n > best_n {
                best_n = n;
                best_i = i;
            }
        }
        assert!(best_n > 0, "no information-set cover");
        let (mask, is) = all_info[best_i].clone();
        chosen.push(is);
        uncovered.retain(|&em| em & mask != 0);
    }
    chosen
}

fn decode_exact(c: &Code, y: &[u16], e: usize, cover: &[InfoSet]) -> Vec<Vec<u16>> {
    let f = c.field;
    let mut seen = HashSet::<u64>::new();
    let mut out = Vec::new();
    for is in cover {
        let mut rhs = vec![0u16; c.d];
        for i in 0..c.d {
            rhs[i] = y[is.pos[i]];
        }
        let mut m = vec![0u16; c.d];
        for i in 0..c.d {
            let mut s = 0u16;
            for j in 0..c.d {
                s = f.add(s, f.mul(is.inv[i][j], rhs[j]));
            }
            m[i] = s;
        }
        let ix = msg_index(&m, c.field.q);
        if !seen.insert(ix) {
            continue;
        }
        let cw = encode_msg(c, &m);
        let mut dd = 0;
        for p in 0..c.l {
            if cw[p] != y[p] {
                dd += 1;
                if dd > e {
                    break;
                }
            }
        }
        if dd <= e {
            out.push(m);
        }
    }
    out
}

fn choose_subsets(v: &[usize], w: usize) -> Vec<Vec<usize>> {
    if w == 0 {
        return vec![vec![]];
    }
    let mut out = Vec::new();
    fn rec(
        v: &[usize],
        start: usize,
        left: usize,
        cur: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if left == 0 {
            out.push(cur.clone());
            return;
        }
        for i in start..=v.len() - left {
            cur.push(v[i]);
            rec(v, i + 1, left - 1, cur, out);
            cur.pop();
        }
    }
    if w <= v.len() {
        rec(v, 0, w, &mut Vec::new(), &mut out);
    }
    out
}

// On Agr(A+rB,c'), pair disagreement with a lift (a,b), a+r b=c',
// is equivalent to B != b.  Thus goodness asks whether B restricted to Agr
// is within epsL of the punctured code.
fn lift_good(c: &Code, bword: &[u16], agr: &[usize], epsl: usize) -> bool {
    for delw in 0..=epsl.min(agr.len()) {
        for del in choose_subsets(agr, delw) {
            let delset = del.iter().copied().collect::<HashSet<_>>();
            let keep = agr
                .iter()
                .copied()
                .filter(|p| !delset.contains(p))
                .collect::<Vec<_>>();
            let rows = keep
                .iter()
                .map(|&p| c.gen[p * c.d..(p + 1) * c.d].to_vec())
                .collect::<Vec<_>>();
            let rhs = keep.iter().map(|&p| bword[p]).collect::<Vec<_>>();
            if consistent(&rows, &rhs, c.d, c.field) {
                return true;
            }
        }
    }
    false
}

#[derive(Clone, Debug)]
struct Eval {
    nclose: usize,
    hist: Vec<usize>,
    bw: [usize; 3],
    badpairs: [usize; 3],
}
fn evaluate(c: &Code, a: &[u16], b: &[u16], e: usize, cover: &[InfoSet]) -> Eval {
    let mut nclose = 0usize;
    let mut hist = vec![0usize; 16];
    let mut bw = [0usize; 3];
    let mut badpairs = [0usize; 3];
    for r in 0..c.field.q {
        let y = (0..c.l)
            .map(|p| c.field.add(a[p], c.field.mul(r, b[p])))
            .collect::<Vec<_>>();
        let list = decode_exact(c, &y, e, cover);
        if list.is_empty() {
            continue;
        }
        nclose += 1;
        if list.len() >= hist.len() {
            hist.resize(list.len() + 1, 0);
        }
        hist[list.len()] += 1;
        let mut challenge_bad = [false; 3];
        for m in list {
            let cp = encode_msg(c, &m);
            let agr = (0..c.l).filter(|&p| y[p] == cp[p]).collect::<Vec<_>>();
            for epsl in 0..3 {
                if !lift_good(c, b, &agr, epsl) {
                    badpairs[epsl] += 1;
                    challenge_bad[epsl] = true;
                }
            }
        }
        for epsl in 0..3 {
            if challenge_bad[epsl] {
                bw[epsl] += 1;
            }
        }
    }
    Eval {
        nclose,
        hist,
        bw,
        badpairs,
    }
}

fn score_key(ev: &Eval) -> (usize, usize, usize, usize) {
    let lmax = ev.hist.iter().rposition(|&x| x > 0).unwrap_or(0);
    (ev.bw[0], ev.badpairs[0], lmax, ev.nclose)
}
fn better(a: &Eval, b: &Eval) -> bool {
    score_key(a).cmp(&score_key(b)) == Ordering::Greater
}

fn two_lines(c: &Code, rng: &mut Rng64) -> (Vec<u16>, Vec<u16>) {
    let (_, a1) = random_codeword(c, rng);
    let (_, b1) = random_codeword(c, rng);
    let (_, a2) = random_codeword(c, rng);
    let (_, b2) = random_codeword(c, rng);
    let mut a = vec![0u16; c.l];
    let mut b = vec![0u16; c.l];
    let mut idx = (0..c.l).collect::<Vec<_>>();
    for i in 0..c.l {
        let j = i + rng.usize(c.l - i);
        idx.swap(i, j);
    }
    for (rank, &p) in idx.iter().enumerate() {
        if rank < c.l / 2 {
            a[p] = a1[p];
            b[p] = b1[p];
        } else {
            a[p] = a2[p];
            b[p] = b2[p];
        }
    }
    (a, b)
}
fn three_lines(c: &Code, rng: &mut Rng64) -> (Vec<u16>, Vec<u16>) {
    let mut aa = Vec::new();
    let mut bb = Vec::new();
    for _ in 0..3 {
        aa.push(random_codeword(c, rng).1);
        bb.push(random_codeword(c, rng).1);
    }
    let mut a = vec![0u16; c.l];
    let mut b = vec![0u16; c.l];
    let mut idx = (0..c.l).collect::<Vec<_>>();
    for i in 0..c.l {
        let j = i + rng.usize(c.l - i);
        idx.swap(i, j);
    }
    for (rank, &p) in idx.iter().enumerate() {
        let z = 3 * rank / c.l;
        a[p] = aa[z][p];
        b[p] = bb[z][p];
    }
    (a, b)
}
fn structured(c: &Code, e: usize, rng: &mut Rng64) -> (Vec<u16>, Vec<u16>) {
    let (_, mut a) = random_codeword(c, rng);
    let (_, mut b) = random_codeword(c, rng);
    let mut idx = (0..c.l).collect::<Vec<_>>();
    for i in 0..c.l {
        let j = i + rng.usize(c.l - i);
        idx.swap(i, j);
    }
    let changes = (e + 1).min(c.l);
    for &p in idx.iter().take(changes) {
        if rng.next() & 1 == 0 {
            let old = a[p];
            while a[p] == old {
                a[p] = rng.elt(c.field);
            }
        } else {
            let old = b[p];
            while b[p] == old {
                b[p] = rng.elt(c.field);
            }
        }
    }
    (a, b)
}

#[derive(Clone)]
struct Best {
    ev: Eval,
    a: Vec<u16>,
    b: Vec<u16>,
    kind: &'static str,
}
fn update_best(best: &mut Option<Best>, ev: Eval, a: &[u16], b: &[u16], kind: &'static str) {
    if best.as_ref().map(|x| better(&ev, &x.ev)).unwrap_or(true) {
        *best = Some(Best {
            ev,
            a: a.to_vec(),
            b: b.to_vec(),
            kind,
        });
    }
}
fn mutate(c: &Code, a: &mut [u16], b: &mut [u16], rng: &mut Rng64) -> (bool, usize, u16) {
    let which = rng.next() & 1 == 0;
    let p = rng.usize(c.l);
    if which {
        let old = a[p];
        while a[p] == old {
            a[p] = rng.elt(c.field);
        }
        (true, p, old)
    } else {
        let old = b[p];
        while b[p] == old {
            b[p] = rng.elt(c.field);
        }
        (false, p, old)
    }
}

fn radii(c: &Code, dmin: usize) -> Vec<(usize, &'static str)> {
    let below = (dmin.saturating_sub(1)) / 2;
    let mut out = vec![(below, "below_half")];
    let delta = dmin as f64 / c.l as f64;
    let jb = (1.0 - (1.0 - delta).sqrt()) * c.l as f64;
    for e in 0..=c.l {
        if 2 * e > dmin && (e as f64) < jb - 1e-12 {
            out.push((e, "above_half"));
        }
    }
    out
}

fn fmt_hist(hist: &[usize]) -> String {
    let mut z = Vec::new();
    for (i, &n) in hist.iter().enumerate() {
        if n > 0 {
            z.push(format!("{i}:{n}"));
        }
    }
    z.join(",")
}
fn print_instance(c: &Code, e: usize, epsl: usize, best: &Best) {
    println!("COUNTEREXAMPLE_BEGIN");
    println!(
        "code={} field={} n={} k={} L={} D={} seed={} e={} epsL={} B={} A={:?} Bword={:?}",
        c.label,
        c.field.name,
        c.n,
        c.k,
        c.l,
        c.d,
        c.seed,
        e,
        epsl,
        best.ev.bw[epsl],
        best.a,
        best.b
    );
    if let Some(g) = &c.gates {
        println!("gates={g:?}");
    } else {
        println!("generator={:?}", c.gen);
    }
    println!("COUNTEREXAMPLE_END");
}

fn run_code(c: Code, trials: usize, master_seed: u64) {
    let dmin = exact_distance(&c);
    println!(
        "CODE code={} field={} n={} k={} L={} D={} seed={} distance={} Delta={:.6}",
        c.label,
        c.field.name,
        c.n,
        c.k,
        c.l,
        c.d,
        c.seed,
        dmin,
        dmin as f64 / c.l as f64
    );
    for (e, zone) in radii(&c, dmin) {
        let cover = info_cover(&c, e);
        println!(
            "RADIUS zone={} e={} delta={:.6} info_sets={}",
            zone,
            e,
            e as f64 / c.l as f64,
            cover.len()
        );
        let mut rng =
            Rng64::new(master_seed ^ c.seed ^ (e as u64).wrapping_mul(0x9e3779b97f4a7c15));
        let mut best: Option<Best> = None;
        let mut agg_hist = vec![0usize; 16];
        let mut reached2 = false;

        // Allocate approximately 1/4 of the trial budget to each generator.
        let q = trials / 4;
        for t in 0..trials {
            let kind;
            let (mut a, mut b) = if t < q {
                kind = "two_lines";
                two_lines(&c, &mut rng)
            } else if t < 2 * q {
                kind = "three_lines";
                three_lines(&c, &mut rng)
            } else if t < 3 * q {
                kind = "structured";
                structured(&c, e, &mut rng)
            } else {
                kind = "hill";
                if let Some(cur) = &best {
                    (cur.a.clone(), cur.b.clone())
                } else {
                    two_lines(&c, &mut rng)
                }
            };

            let mut ev = evaluate(&c, &a, &b, e, &cover);

            if kind == "hill" {
                let (which, p, old) = mutate(&c, &mut a, &mut b, &mut rng);
                let nev = evaluate(&c, &a, &b, e, &cover);
                if better(&nev, &ev) {
                    ev = nev;
                } else {
                    if which {
                        a[p] = old
                    } else {
                        b[p] = old
                    }
                }
            }

            if ev.hist.iter().enumerate().any(|(i, &n)| i >= 2 && n > 0) {
                reached2 = true;
            }
            if ev.hist.len() > agg_hist.len() {
                agg_hist.resize(ev.hist.len(), 0);
            }
            for i in 0..ev.hist.len() {
                agg_hist[i] += ev.hist[i];
            }
            update_best(&mut best, ev, &a, &b, kind);
        }

        let b = best.unwrap();
        println!("RESULT trials={} reached_list_ge2={} aggregate_hist={} best_source={} best_N_close={} best_hist={} B0={} B1={} B2={} B0_over_L={:.6} B1_over_L={:.6} B2_over_L={:.6} badpairs0={} badpairs1={} badpairs2={}",
            trials,reached2,fmt_hist(&agg_hist),b.kind,b.ev.nclose,fmt_hist(&b.ev.hist),
            b.ev.bw[0],b.ev.bw[1],b.ev.bw[2],
            b.ev.bw[0] as f64/c.l as f64,b.ev.bw[1] as f64/c.l as f64,b.ev.bw[2] as f64/c.l as f64,
            b.ev.badpairs[0],b.ev.badpairs[1],b.ev.badpairs[2]);

        for epsl in 0..3 {
            if b.ev.bw[epsl] > c.l {
                print_instance(&c, e, epsl, &b);
            }
        }
    }
}

fn main() {
    let trials: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let cases = [
        (
            GF {
                m: 5,
                poly: 0b100101,
                q: 32,
                name: "GF32",
            },
            2usize,
            2usize,
            false,
        ),
        (
            GF {
                m: 6,
                poly: 0b1000011,
                q: 64,
                name: "GF64",
            },
            2usize,
            2usize,
            false,
        ),
        (
            GF {
                m: 8,
                poly: 0x11b,
                q: 256,
                name: "GF256",
            },
            1usize,
            3usize,
            false,
        ),
        (
            GF {
                m: 6,
                poly: 0b1000011,
                q: 64,
                name: "GF64",
            },
            2usize,
            3usize,
            true,
        ),
    ];
    println!("brief13c_partD trials_per_code_radius={trials}");
    for (ci, (f, n, k, optional)) in cases.into_iter().enumerate() {
        if optional && std::env::var("BRIEF13C_OPTIONAL").ok().as_deref() != Some("1") {
            println!("OPTIONAL_SKIPPED field={} n={} k={}", f.name, n, k);
            continue;
        }
        println!("CASE field={} n={} k={}", f.name, n, k);
        for fam in 0..5 {
            let seed = 0x13c0_0000u64 ^ ((ci as u64) << 24) ^ fam as u64;
            run_code(spark_code(n, k, f, seed), trials, seed ^ 0xaaaa);
        }
        for fam in 0..5 {
            let seed = 0x13c8_0000u64 ^ ((ci as u64) << 24) ^ fam as u64;
            run_code(
                random_code(1usize << (n + k), 1usize << n, f, seed),
                trials,
                seed ^ 0x5555,
            );
        }
    }
}

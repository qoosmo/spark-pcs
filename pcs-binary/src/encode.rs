use crate::{
    field::{batch_inverse, F128},
    gates::Gate,
};
use rand::RngCore;
use rayon::prelude::*;

/// A level stores one gate per parent node.
#[derive(Clone, Debug)]
pub struct GateLevel {
    pub gates: Vec<Gate>,
}

#[derive(Clone, Debug)]
pub struct GateFamily {
    pub n: usize,
    pub k: usize,
    /// levels[0] expands the repetition base 2^k -> 2^(k+1), etc.
    pub levels: Vec<GateLevel>,
}

/// Domain-separated key for all gates at one level.
///
/// SPARK v0.7 models BLAKE3 as a random oracle.  The tuple
/// (version, seed, setup_counter, level_idx) is encoded injectively using a
/// fixed ASCII version tag followed by fixed-width little-endian integers.
#[inline]
pub fn derive_gate_level_key(seed: u64, setup_counter: u64, level_idx: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"SPARK-GATE-v0.7");
    h.update(&seed.to_le_bytes());
    h.update(&setup_counter.to_le_bytes());
    h.update(&(level_idx as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

/// Derive one gate from a precomputed level key.
///
/// The normal path is one keyed BLAKE3 call on the 8-byte node index.  If the
/// two 128-bit outputs coincide, retry with the disjoint 16-byte domain
/// (node_index || retry_counter), exactly as specified for v0.7.
#[inline]
pub fn derive_raw_gate_from_level_key(level_key: &[u8; 32], gate_idx: usize) -> (F128, F128) {
    let q = (gate_idx as u64).to_le_bytes();
    let mut d = blake3::keyed_hash(level_key, &q);
    let mut retry = 0u64;

    loop {
        let bytes = d.as_bytes();
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&bytes[..16]);
        b.copy_from_slice(&bytes[16..]);
        let t0 = F128(u128::from_le_bytes(a));
        let t1 = F128(u128::from_le_bytes(b));
        if t0 != t1 {
            return (t0, t1);
        }

        retry = retry.checked_add(1).expect("gate retry counter exhausted");
        let mut retry_input = [0u8; 16];
        retry_input[..8].copy_from_slice(&q);
        retry_input[8..].copy_from_slice(&retry.to_le_bytes());
        d = blake3::keyed_hash(level_key, &retry_input);
    }
}

/// Deterministic structural points for one gate, derived from the public seed.
///
/// This compatibility entry point derives the level key and then the node gate.
/// Hot paths should derive the level key once and reuse it for all nodes at that
/// level.
pub fn derive_raw_gate_with_counter(
    seed: u64,
    setup_counter: u64,
    level_idx: usize,
    gate_idx: usize,
) -> (F128, F128) {
    let level_key = derive_gate_level_key(seed, setup_counter, level_idx);
    derive_raw_gate_from_level_key(&level_key, gate_idx)
}

/// Compatibility wrapper: unchecked counter 0.
pub fn derive_raw_gate(seed: u64, level_idx: usize, gate_idx: usize) -> (F128, F128) {
    derive_raw_gate_with_counter(seed, 0, level_idx, gate_idx)
}

#[derive(Clone, Debug)]
pub struct CheckedSetup {
    pub family: GateFamily,
    pub counter: u64,
    pub check_time: std::time::Duration,
}

#[inline]
fn point_of(pair: (F128, F128), bit: usize) -> F128 {
    if bit == 0 {
        pair.0
    } else {
        pair.1
    }
}

/// In characteristic two the determinant sign disappears, so det is the XOR
/// of the 24 permutation products.  No inversion is needed for the setup test.
fn det4(m: [[F128; 4]; 4]) -> F128 {
    const P: [[usize; 4]; 24] = [
        [0, 1, 2, 3],
        [0, 1, 3, 2],
        [0, 2, 1, 3],
        [0, 2, 3, 1],
        [0, 3, 1, 2],
        [0, 3, 2, 1],
        [1, 0, 2, 3],
        [1, 0, 3, 2],
        [1, 2, 0, 3],
        [1, 2, 3, 0],
        [1, 3, 0, 2],
        [1, 3, 2, 0],
        [2, 0, 1, 3],
        [2, 0, 3, 1],
        [2, 1, 0, 3],
        [2, 1, 3, 0],
        [2, 3, 0, 1],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [3, 0, 2, 1],
        [3, 1, 0, 2],
        [3, 1, 2, 0],
        [3, 2, 0, 1],
        [3, 2, 1, 0],
    ];
    let mut d = F128::ZERO;
    for p in P {
        d = d + m[0][p[0]] * m[1][p[1]] * m[2][p[2]] * m[3][p[3]];
    }
    d
}

fn checked_prefix_is_mds_from_raw(k: usize, l0: &[(F128, F128)], l1: &[(F128, F128)]) -> bool {
    let copies = 1usize << k;
    if l0.len() != copies || l1.len() != 2 * copies {
        return false;
    }

    // C1 is [2^(k+1),2]: MDS iff every structural point is distinct.
    let mut c1 = Vec::with_capacity(2 * copies);
    for &(a, b) in l0 {
        c1.push(a);
        c1.push(b);
    }
    c1.sort_unstable_by_key(|x| x.0);
    if c1.windows(2).any(|w| w[0] == w[1]) {
        return false;
    }

    // Coordinates of C2.  A parent p at level 1 is the C1 coordinate
    // p=(beta,b1); its two children use the fresh level-1 point b2.
    // The generator row is (1,y1,y2,y1*y2).
    let mut rows = Vec::with_capacity(4 * copies);
    for p in 0..(2 * copies) {
        let beta = p >> 1;
        let b1 = p & 1;
        let y1 = point_of(l0[beta], b1);
        for b2 in 0..2 {
            let y2 = point_of(l1[p], b2);
            rows.push([F128::ONE, y1, y2, y1 * y2]);
        }
    }

    let n = rows.len();
    for a in 0..n - 3 {
        for b in a + 1..n - 2 {
            for c in b + 1..n - 1 {
                for d in c + 1..n {
                    if det4([rows[a], rows[b], rows[c], rows[d]]) == F128::ZERO {
                        return false;
                    }
                }
            }
        }
    }
    true
}

pub fn checked_prefix_is_mds(seed: u64, k: usize, counter: u64) -> bool {
    let key0 = derive_gate_level_key(seed, counter, 0);
    let key1 = derive_gate_level_key(seed, counter, 1);
    let l0 = (0..(1usize << k))
        .map(|j| derive_raw_gate_from_level_key(&key0, j))
        .collect::<Vec<_>>();
    let l1 = (0..(1usize << (k + 1)))
        .map(|j| derive_raw_gate_from_level_key(&key1, j))
        .collect::<Vec<_>>();
    checked_prefix_is_mds_from_raw(k, &l0, &l1)
}


/// Return the 8-dimensional C3 generator row for one output position.
#[inline]
fn c3_row_from_raw(
    k: usize,
    l0: &[(F128, F128)],
    l1: &[(F128, F128)],
    l2: &[(F128, F128)],
    pos: usize,
) -> [F128; 8] {
    let beta = pos >> 3;
    let b1 = (pos >> 2) & 1;
    let b2 = (pos >> 1) & 1;
    let b3 = pos & 1;

    debug_assert!(beta < (1usize << k));
    let p1 = (beta << 1) | b1;
    let p2 = (p1 << 1) | b2;

    let y1 = point_of(l0[beta], b1);
    let y2 = point_of(l1[p1], b2);
    let y3 = point_of(l2[p2], b3);

    [
        F128::ONE,
        y1,
        y2,
        y1 * y2,
        y3,
        y1 * y3,
        y2 * y3,
        y1 * y2 * y3,
    ]
}

#[inline]
fn rows8_nonsingular(rows: &[[F128; 8]; 32], ix: [usize; 8]) -> bool {
    let mut a = [
        rows[ix[0]], rows[ix[1]], rows[ix[2]], rows[ix[3]],
        rows[ix[4]], rows[ix[5]], rows[ix[6]], rows[ix[7]],
    ];

    for col in 0..8 {
        let mut pivot = col;
        while pivot < 8 && a[pivot][col] == F128::ZERO {
            pivot += 1;
        }
        if pivot == 8 {
            return false;
        }
        if pivot != col {
            a.swap(pivot, col);
        }

        let p = a[col][col];
        for r in (col + 1)..8 {
            let x = a[r][col];
            if x == F128::ZERO {
                continue;
            }
            a[r][col] = F128::ZERO;
            for j in (col + 1)..8 {
                a[r][j] = p * a[r][j] + x * a[col][j];
            }
        }
    }
    true
}

fn c3_is_mds_from_raw(
    k: usize,
    l0: &[(F128, F128)],
    l1: &[(F128, F128)],
    l2: &[(F128, F128)],
) -> bool {
    let copies = 1usize << k;
    if k != 2 || l0.len() != copies || l1.len() != 2 * copies || l2.len() != 4 * copies {
        return false;
    }

    let rows_vec = (0..32)
        .map(|pos| c3_row_from_raw(k, l0, l1, l2, pos))
        .collect::<Vec<_>>();
    let rows: [[F128; 8]; 32] = rows_vec.try_into().expect("C3 has 32 rows");

    use std::sync::atomic::{AtomicBool, Ordering};
    let ok = AtomicBool::new(true);

    (0usize..=24).into_par_iter().for_each(|a| {
        if !ok.load(Ordering::Relaxed) { return; }
        for b in (a + 1)..=25 {
            if !ok.load(Ordering::Relaxed) { return; }
            for c in (b + 1)..=26 {
                for d in (c + 1)..=27 {
                    for e in (d + 1)..=28 {
                        for f in (e + 1)..=29 {
                            for g in (f + 1)..=30 {
                                for h in (g + 1)..=31 {
                                    if !rows8_nonsingular(&rows, [a,b,c,d,e,f,g,h]) {
                                        ok.store(false, Ordering::Relaxed);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    ok.load(Ordering::Relaxed)
}

fn checked_prefix3_is_mds_from_raw(
    k: usize,
    l0: &[(F128, F128)],
    l1: &[(F128, F128)],
    l2: &[(F128, F128)],
) -> bool {
    checked_prefix_is_mds_from_raw(k, l0, l1) && c3_is_mds_from_raw(k, l0, l1, l2)
}

pub fn checked_prefix3_is_mds(seed: u64, k: usize, counter: u64) -> bool {
    let key0 = derive_gate_level_key(seed, counter, 0);
    let key1 = derive_gate_level_key(seed, counter, 1);
    let key2 = derive_gate_level_key(seed, counter, 2);
    let l0 = (0..(1usize << k))
        .map(|j| derive_raw_gate_from_level_key(&key0, j))
        .collect::<Vec<_>>();
    let l1 = (0..(1usize << (k + 1)))
        .map(|j| derive_raw_gate_from_level_key(&key1, j))
        .collect::<Vec<_>>();
    let l2 = (0..(1usize << (k + 2)))
        .map(|j| derive_raw_gate_from_level_key(&key2, j))
        .collect::<Vec<_>>();
    checked_prefix3_is_mds_from_raw(k, &l0, &l1, &l2)
}

impl GateFamily {
    /// Build a family using an explicit accepted checked-setup counter.
    pub fn from_seed_and_counter(n: usize, k: usize, seed: u64, setup_counter: u64) -> Self {
        assert!(n >= 2, "checked i0=2 setup requires n>=2");
        let total_gates: usize = (0..n).map(|i| 1usize << (k + i)).sum();
        let mut raw = Vec::with_capacity(total_gates);
        let mut denoms = Vec::with_capacity(total_gates);
        for i in 0..n {
            let parents = 1usize << (k + i);
            let level_key = derive_gate_level_key(seed, setup_counter, i);
            for j in 0..parents {
                let (t0, t1) = derive_raw_gate_from_level_key(&level_key, j);
                raw.push((t0, t1));
                denoms.push(t1 + t0);
            }
        }
        let invs = batch_inverse(&denoms);
        let mut cursor = 0usize;
        let mut levels = Vec::with_capacity(n);
        for i in 0..n {
            let parents = 1usize << (k + i);
            let gates = (0..parents)
                .map(|j| {
                    let (t0, t1) = raw[cursor + j];
                    Gate::new(t0, t1, invs[cursor + j])
                })
                .collect();
            cursor += parents;
            levels.push(GateLevel { gates });
        }
        Self { n, k, levels }
    }

    /// Deterministic checked setup for Theorem 3.19 with i0=2.
    /// Search a public counter until C1 and C2 are MDS, then build the full family.
    pub fn from_seed_checked(n: usize, k: usize, seed: u64) -> CheckedSetup {
        assert!(n >= 2, "checked i0=2 setup requires n>=2");
        let t = std::time::Instant::now();
        let mut counter = 0u64;
        loop {
            if checked_prefix_is_mds(seed, k, counter) {
                let check_time = t.elapsed();
                let family = Self::from_seed_and_counter(n, k, seed, counter);
                return CheckedSetup {
                    family,
                    counter,
                    check_time,
                };
            }
            counter = counter
                .checked_add(1)
                .expect("checked-setup counter exhausted");
        }
    }

    /// Deterministic checked setup for Theorem 3.19 with i0=3 (Brief 10).
    pub fn from_seed_checked_i0_3(n: usize, k: usize, seed: u64) -> CheckedSetup {
        assert!(n >= 3, "checked i0=3 setup requires n>=3");
        assert!(k == 2, "Brief-10 exhaustive C3 checker is specialized to k=2");
        let t = std::time::Instant::now();
        let mut counter = 0u64;
        loop {
            if checked_prefix3_is_mds(seed, k, counter) {
                let check_time = t.elapsed();
                let family = Self::from_seed_and_counter(n, k, seed, counter);
                return CheckedSetup {
                    family,
                    counter,
                    check_time,
                };
            }
            counter = counter
                .checked_add(1)
                .expect("checked-setup counter exhausted");
        }
    }

    /// Random gates with one batch inversion for all denominators in the family.
    pub fn random<R: RngCore>(n: usize, k: usize, rng: &mut R) -> Self {
        let total_gates: usize = (0..n).map(|i| 1usize << (k + i)).sum();
        let mut raw = Vec::with_capacity(total_gates);
        let mut denoms = Vec::with_capacity(total_gates);
        for i in 0..n {
            let parents = 1usize << (k + i);
            for _ in 0..parents {
                let t0 = F128::random(rng);
                let mut t1 = F128::random(rng);
                while t1 == t0 {
                    t1 = F128::random(rng);
                }
                raw.push((t0, t1));
                denoms.push(t1 + t0);
            }
        }
        let invs = batch_inverse(&denoms);

        let mut cursor = 0usize;
        let mut levels = Vec::with_capacity(n);
        for i in 0..n {
            let parents = 1usize << (k + i);
            let gates = (0..parents)
                .map(|j| {
                    let (t0, t1) = raw[cursor + j];
                    Gate::new(t0, t1, invs[cursor + j])
                })
                .collect();
            cursor += parents;
            levels.push(GateLevel { gates });
        }
        Self { n, k, levels }
    }

    /// Deterministic public-seed gate family. One batch inversion for all denominators.
    pub fn from_seed(n: usize, k: usize, seed: u64) -> Self {
        let total_gates: usize = (0..n).map(|i| 1usize << (k + i)).sum();
        let mut raw = Vec::with_capacity(total_gates);
        let mut denoms = Vec::with_capacity(total_gates);
        for i in 0..n {
            let parents = 1usize << (k + i);
            let level_key = derive_gate_level_key(seed, 0, i);
            for j in 0..parents {
                let (t0, t1) = derive_raw_gate_from_level_key(&level_key, j);
                raw.push((t0, t1));
                denoms.push(t1 + t0);
            }
        }
        let invs = batch_inverse(&denoms);
        let mut cursor = 0usize;
        let mut levels = Vec::with_capacity(n);
        for i in 0..n {
            let parents = 1usize << (k + i);
            let gates = (0..parents)
                .map(|j| {
                    let (t0, t1) = raw[cursor + j];
                    Gate::new(t0, t1, invs[cursor + j])
                })
                .collect();
            cursor += parents;
            levels.push(GateLevel { gates });
        }
        Self { n, k, levels }
    }
}

/// Flat ping-pong encoder.
///
/// The v0.3 encoder represented the recursion as Vec<Vec<F128>> and allocated one
/// vector for every polynomial fragment at every level. Here the complete encoded
/// word lives in two flat buffers of fixed size. Each level is one parallel pass.
pub fn encode(coeffs: &[F128], family: &GateFamily) -> Vec<F128> {
    assert_eq!(coeffs.len(), 1usize << family.n);
    let copies = 1usize << family.k;
    let total = coeffs.len() * copies;

    let mut src = vec![F128::ZERO; total];
    src.par_chunks_exact_mut(copies)
        .zip(coeffs.par_iter().copied())
        .for_each(|(dst, c)| dst.fill(c));

    let mut dst = vec![F128::ZERO; total];

    for (level_idx, level) in family.levels.iter().enumerate() {
        let parents = 1usize << (family.k + level_idx);
        let pair_span = 2 * parents;
        assert_eq!(level.gates.len(), parents);
        assert_eq!(total % pair_span, 0);

        dst.par_chunks_exact_mut(2)
            .enumerate()
            .for_each(|(out_pair, out)| {
                let block_pair = out_pair / parents;
                let p = out_pair % parents;
                let base = block_pair * pair_span;
                let u = src[base + p];
                let v = src[base + parents + p];
                let (a, b) = level.gates[p].encode_pair(u, v);
                out[0] = a;
                out[1] = b;
            });

        std::mem::swap(&mut src, &mut dst);
    }

    src
}

/// Evaluate multilinear monomial coefficients at z=(z1,...,zn).
/// Coefficient order has xn as the least-significant variable, matching `encode`.
pub fn evaluate(coeffs: &[F128], z: &[F128]) -> F128 {
    assert_eq!(coeffs.len(), 1usize << z.len());
    let mut layer = coeffs.to_vec();
    for &x in z.iter().rev() {
        layer = layer.par_chunks_exact(2).map(|p| p[0] + x * p[1]).collect();
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold::fold_all;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn lengths_match() {
        let mut rng = StdRng::seed_from_u64(1);
        for n in 1..6 {
            let k = 2;
            let fam = GateFamily::random(n, k, &mut rng);
            let coeffs = (0..(1usize << n))
                .map(|_| F128::random(&mut rng))
                .collect::<Vec<_>>();
            let enc = encode(&coeffs, &fam);
            assert_eq!(enc.len(), 1usize << (n + k));
        }
    }

    #[test]
    fn encode_then_fold_matches_direct_evaluation() {
        let mut rng = StdRng::seed_from_u64(42);
        for n in 1..6 {
            let k = 2;
            let fam = GateFamily::random(n, k, &mut rng);
            let coeffs = (0..(1usize << n))
                .map(|_| F128::random(&mut rng))
                .collect::<Vec<_>>();
            let z = (0..n).map(|_| F128::random(&mut rng)).collect::<Vec<_>>();
            let enc = encode(&coeffs, &fam);
            let folded = fold_all(enc, &fam, &z);
            let y = evaluate(&coeffs, &z);
            assert!(folded.iter().all(|&v| v == y));
        }
    }

    #[test]
    fn checked_setup_accepts_and_rechecks() {
        let cs = GateFamily::from_seed_checked(4, 2, 12345);
        assert!(checked_prefix_is_mds(12345, 2, cs.counter));
        assert_eq!(cs.family.n, 4);
        assert_eq!(cs.family.k, 2);
    }

    #[test]
    fn checked_setup_rejects_forced_c1_collision() {
        let k = 2usize;
        let mut l0 = vec![(F128::ZERO, F128::ONE); 1usize << k];
        // Force duplicate structural points across two different C1 coordinates.
        l0[1].0 = l0[0].0;
        let l1 = (0..(1usize << (k + 1)))
            .map(|i| {
                let a = F128((10 + i * 2) as u128);
                let b = F128((11 + i * 2) as u128);
                (a, b)
            })
            .collect::<Vec<_>>();
        assert!(!checked_prefix_is_mds_from_raw(k, &l0, &l1));
    }

    #[test]
    fn brief10_c3_closed_form_rows_match_encode() {
        let k = 2usize;
        let seed = 0xB10u64;
        let ctr = 0u64;

        let key0 = derive_gate_level_key(seed, ctr, 0);
        let key1 = derive_gate_level_key(seed, ctr, 1);
        let key2 = derive_gate_level_key(seed, ctr, 2);
        let l0 = (0..(1usize << k))
            .map(|j| derive_raw_gate_from_level_key(&key0, j))
            .collect::<Vec<_>>();
        let l1 = (0..(1usize << (k + 1)))
            .map(|j| derive_raw_gate_from_level_key(&key1, j))
            .collect::<Vec<_>>();
        let l2 = (0..(1usize << (k + 2)))
            .map(|j| derive_raw_gate_from_level_key(&key2, j))
            .collect::<Vec<_>>();

        let fam = GateFamily::from_seed_and_counter(3, k, seed, ctr);

        for col in 0..8 {
            let mut coeffs = vec![F128::ZERO; 8];
            coeffs[col] = F128::ONE;
            let word = encode(&coeffs, &fam);
            assert_eq!(word.len(), 32);
            for pos in 0..32 {
                let row = c3_row_from_raw(k, &l0, &l1, &l2, pos);
                assert_eq!(word[pos], row[col], "column={col} pos={pos}");
            }
        }
    }

    #[test]
    fn brief10_forced_level3_coincidence_is_rejected() {
        let k = 2usize;
        let l0 = (0..4)
            .map(|i| (F128((10 + 2*i) as u128), F128((11 + 2*i) as u128)))
            .collect::<Vec<_>>();
        let l1 = (0..8)
            .map(|i| (F128((100 + 2*i) as u128), F128((101 + 2*i) as u128)))
            .collect::<Vec<_>>();
        let mut l2 = (0..16)
            .map(|i| (F128((1000 + 2*i) as u128), F128((1001 + 2*i) as u128)))
            .collect::<Vec<_>>();

        l2[0].1 = l2[0].0;
        assert!(!c3_is_mds_from_raw(k, &l0, &l1, &l2));
    }

    #[test]
    #[ignore = "exhaustive C(32,8) Brief-10 checked setup; run in release mode"]
    fn brief10_honest_i0_3_setup_passes() {
        let seed = 1u64;
        let cs = GateFamily::from_seed_checked_i0_3(20, 2, seed);
        assert!(checked_prefix3_is_mds(seed, 2, cs.counter));
        assert_eq!(cs.family.n, 20);
        assert_eq!(cs.family.k, 2);
    }

    #[test]
    fn v07_keyed_gate_derivation_is_deterministic_and_distinct() {
        let seed = 0x5350_4152_4b07u64;
        let ctr = 7u64;
        for level in 0..8 {
            let key = derive_gate_level_key(seed, ctr, level);
            for q in 0..256usize {
                let a = derive_raw_gate_from_level_key(&key, q);
                let b = derive_raw_gate_with_counter(seed, ctr, level, q);
                assert_eq!(a, b);
                assert_ne!(a.0, a.1);
            }
        }
    }

    /// Audit requested for v0.7: check the complete n=20,k=2 public gate
    /// domain for duplicate (t0,t1) pairs.  Ignored by default because it scans
    /// 4,194,300 gates; run explicitly in release mode before freezing v0.7.
    #[test]
    #[ignore = "full n=20 collision audit; run explicitly in release mode"]
    fn v07_gate_outputs_no_collisions_n20() {
        let n = 20usize;
        let k = 2usize;
        let seed = 1u64;
        let setup = GateFamily::from_seed_checked(2, k, seed);
        let ctr = setup.counter;

        let total: usize = (0..n).map(|level| 1usize << (k + level)).sum();
        let mut all = Vec::with_capacity(total);
        for level in 0..n {
            let key = derive_gate_level_key(seed, ctr, level);
            let parents = 1usize << (k + level);
            for q in 0..parents {
                let (t0, t1) = derive_raw_gate_from_level_key(&key, q);
                assert_ne!(t0, t1);
                all.push((t0.0, t1.0));
            }
        }
        all.sort_unstable();
        assert!(all.windows(2).all(|w| w[0] != w[1]));
    }
}

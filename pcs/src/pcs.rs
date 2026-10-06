//! Matrix-gate folding PCS: commit, open at the folding point z = (z_1, ..., z_n), verify.
//!
//! Layout. Positions of layer j (0 <= j <= n) are indices of length 2^(k+n-j) whose bits are
//! (beta, theta_n, ..., theta_{j+1}), theta_{j+1} least significant. Folding round j removes x_j
//! and pairs positions (2q, 2q+1) of layer j-1 into position q of layer j. Merkle leaves are
//! these pairs (blocks).

use crate::field::{Fe3, Fp};
use crate::gates::{gate, level_gates};
use crate::merkle::{self, Hash, MerkleTree};
use crate::params::Params;
use crate::transcript::Transcript;

pub struct Committed {
    pub e0: Vec<Fp>,
    pub tree: MerkleTree,
}

pub struct Query {
    pub base_block: (Fp, Fp),
    pub base_path: Vec<Hash>,
    pub ext_blocks: Vec<(Fe3, Fe3, Vec<Hash>)>, // layers 1..n-1
}

pub struct Proof {
    pub roots: Vec<Hash>, // layers 1..n-1
    pub last: Vec<Fe3>,   // layer n, 2^k entries (all equal for an honest prover)
    pub queries: Vec<Query>,
}

/// E_0 = Enc_n(F): F evaluated at the structural points of the gate tree, 2^k copies.
pub fn encode(params: &Params, coeffs: &[Fp]) -> Vec<Fp> {
    let (n, k) = (params.n, params.k);
    assert_eq!(coeffs.len(), 1 << n);
    let len = 1usize << (n + k);
    let mut a = Vec::with_capacity(len);
    for _ in 0..(1usize << k) {
        a.extend_from_slice(coeffs);
    }
    // substitute x_n, x_{n-1}, ..., x_1 (coefficient bit j-1 <-> x_j)
    for j in (1..=n).rev() {
        let size = 1usize << j;
        let half = size / 2;
        let nodes = len / size;
        for node in 0..nodes {
            let g = gate(&params.seed, j, node);
            let base = node * size;
            for i in 0..half {
                let u = a[base + i];
                let v = a[base + half + i];
                a[base + i] = u.add(g.t0.mul(v));
                a[base + half + i] = u.add(g.t1.mul(v));
            }
        }
    }
    a
}

fn base_leaves(e: &[Fp]) -> Vec<Vec<u8>> {
    e.chunks(2).map(|c| [c[0].to_bytes(), c[1].to_bytes()].concat()).collect()
}

fn ext_leaves(e: &[Fe3]) -> Vec<Vec<u8>> {
    e.chunks(2).map(|c| [c[0].to_bytes(), c[1].to_bytes()].concat()).collect()
}

fn base_leaf(w0: Fp, w1: Fp) -> Vec<u8> {
    [w0.to_bytes(), w1.to_bytes()].concat()
}

fn ext_leaf(w0: Fe3, w1: Fe3) -> Vec<u8> {
    [w0.to_bytes(), w1.to_bytes()].concat().to_vec()
}

pub fn commit(params: &Params, coeffs: &[Fp]) -> (Hash, Committed) {
    let e0 = encode(params, coeffs);
    let tree = MerkleTree::new(&base_leaves(&e0));
    (tree.root(), Committed { e0, tree })
}

fn transcript_start(params: &Params, root0: &Hash) -> Transcript {
    let mut t = Transcript::new(b"spark-pcs-v1");
    t.absorb(&(params.n as u64).to_le_bytes());
    t.absorb(&(params.k as u64).to_le_bytes());
    t.absorb(&(params.s as u64).to_le_bytes());
    t.absorb(&params.seed);
    t.absorb(root0);
    t
}

#[inline]
fn fold_value(w0: Fe3, w1: Fe3, z: Fe3, t0: Fp, inv_diff: Fp) -> Fe3 {
    // w0 + (z - t0)/(t1 - t0) * (w1 - w0)  ==  gate rule of A_j at x_j = z
    let lam = z.sub(Fe3::from_base(t0)).mul_base(inv_diff);
    w0.add(lam.mul(w1.sub(w0)))
}

/// Opening at z = (z_1..z_n), the folding challenges. Returns (y, z, proof).
pub fn prove(params: &Params, c: &Committed) -> (Fe3, Vec<Fe3>, Proof) {
    prove_inner(params, &c.e0, &c.tree, &c.e0)
}

/// `open_e0` is what gets opened against `tree0`; `fold_e0` is what the prover folds.
/// They differ only for a cheating prover (used in tests).
pub fn prove_inner(
    params: &Params,
    open_e0: &[Fp],
    tree0: &MerkleTree,
    fold_e0: &[Fp],
) -> (Fe3, Vec<Fe3>, Proof) {
    let (n, k) = (params.n, params.k);
    let len = 1usize << (n + k);
    let mut t = transcript_start(params, &tree0.root());
    let mut zs = Vec::with_capacity(n);
    let mut layers: Vec<Vec<Fe3>> = Vec::with_capacity(n);
    let mut trees: Vec<MerkleTree> = Vec::new();
    let mut roots = Vec::new();
    for j in 1..=n {
        let z = t.squeeze_ext();
        zs.push(z);
        let nodes = len >> j;
        let g = level_gates(&params.seed, j, nodes);
        let next: Vec<Fe3> = (0..nodes)
            .map(|q| {
                let (w0, w1) = if j == 1 {
                    (Fe3::from_base(fold_e0[2 * q]), Fe3::from_base(fold_e0[2 * q + 1]))
                } else {
                    let prev = &layers[j - 2];
                    (prev[2 * q], prev[2 * q + 1])
                };
                fold_value(w0, w1, z, g.t0[q], g.inv_diff[q])
            })
            .collect();
        if j < n {
            let tree = MerkleTree::new(&ext_leaves(&next));
            t.absorb(&tree.root());
            roots.push(tree.root());
            trees.push(tree);
        } else {
            for e in &next {
                t.absorb(&e.to_bytes());
            }
        }
        layers.push(next);
    }
    let last = layers[n - 1].clone();
    let y = last[0];
    let mut queries = Vec::with_capacity(params.s);
    for _ in 0..params.s {
        let omega = t.squeeze_index(n + k);
        let q1 = omega >> 1;
        let base_block = (open_e0[2 * q1], open_e0[2 * q1 + 1]);
        let base_path = tree0.open(q1);
        let mut ext_blocks = Vec::with_capacity(n - 1);
        for j in 2..=n {
            let q = omega >> j;
            let layer = &layers[j - 2];
            ext_blocks.push((layer[2 * q], layer[2 * q + 1], trees[j - 2].open(q)));
        }
        queries.push(Query { base_block, base_path, ext_blocks });
    }
    (y, zs, Proof { roots, last, queries })
}

/// Returns (y, z) if the proof is accepted.
pub fn verify(params: &Params, root0: &Hash, proof: &Proof) -> Result<(Fe3, Vec<Fe3>), String> {
    let (n, k) = (params.n, params.k);
    if proof.roots.len() != n - 1 || proof.last.len() != 1 << k || proof.queries.len() != params.s {
        return Err("malformed proof".into());
    }
    let mut t = transcript_start(params, root0);
    let mut zs = Vec::with_capacity(n);
    for j in 1..=n {
        zs.push(t.squeeze_ext());
        if j < n {
            t.absorb(&proof.roots[j - 1]);
        } else {
            for e in &proof.last {
                t.absorb(&e.to_bytes());
            }
        }
    }
    let y = proof.last[0];
    if proof.last.iter().any(|&e| e != y) {
        return Err("last layer is not constant".into());
    }
    for (qi, qp) in proof.queries.iter().enumerate() {
        let omega = t.squeeze_index(n + k);
        if qp.ext_blocks.len() != n - 1 {
            return Err("malformed query".into());
        }
        for j in 1..=n {
            let q = omega >> j;
            let (w0, w1) = if j == 1 {
                let (a, b) = qp.base_block;
                if !merkle::verify(root0, q, &base_leaf(a, b), &qp.base_path) {
                    return Err(format!("query {qi}: Merkle path of layer 0"));
                }
                (Fe3::from_base(a), Fe3::from_base(b))
            } else {
                let (a, b, path) = &qp.ext_blocks[j - 2];
                if !merkle::verify(&proof.roots[j - 2], q, &ext_leaf(*a, *b), path) {
                    return Err(format!("query {qi}: Merkle path of layer {}", j - 1));
                }
                (*a, *b)
            };
            let g = gate(&params.seed, j, q);
            let e = fold_value(w0, w1, zs[j - 1], g.t0, g.t1.sub(g.t0).inv());
            let expected = if j < n {
                let (a, b, _) = &qp.ext_blocks[j - 1];
                if q & 1 == 0 { *a } else { *b }
            } else {
                proof.last[q]
            };
            if e != expected {
                return Err(format!("query {qi}: gate check failed at layer {j}"));
            }
        }
    }
    Ok((y, zs))
}

/// Direct evaluation of the multilinear F (coefficient bit j-1 <-> x_j) at z.
pub fn eval_multilinear(coeffs: &[Fp], z: &[Fe3]) -> Fe3 {
    let mut cur: Vec<Fe3> = coeffs.iter().map(|&c| Fe3::from_base(c)).collect();
    for zj in z {
        cur = cur.chunks(2).map(|c| c[0].add(zj.mul(c[1]))).collect();
    }
    cur[0]
}

pub fn proof_size_bytes(p: &Proof) -> usize {
    let mut s = 32 * p.roots.len() + 24 * p.last.len();
    for q in &p.queries {
        s += 16 + 32 * q.base_path.len();
        for (_, _, path) in &q.ext_blocks {
            s += 48 + 32 * path.len();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(n: usize, k: usize, s: usize) -> Params {
        Params { n, k, s, seed: [7u8; 32], delta_star: 0.5, delta: 0.2, log2_bad_challenge: -130.0 }
    }

    fn poly(n: usize, salt: u64) -> Vec<Fp> {
        (0..1u64 << n).map(|i| Fp::new(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt)).collect()
    }

    #[test]
    fn honest_proof_verifies_and_opens_f_at_z() {
        let p = params(6, 2, 40);
        let f = poly(6, 1);
        let (root, c) = commit(&p, &f);
        let (y, z, proof) = prove(&p, &c);
        let (y2, z2) = verify(&p, &root, &proof).expect("honest proof rejected");
        assert_eq!(y, y2);
        assert_eq!(z, z2);
        assert_eq!(y, eval_multilinear(&f, &z));
    }

    #[test]
    fn closed_form_matches_point_evaluation() {
        // Enc_n(F)(omega) = F(r(omega)), r_j = t_j^{theta_j}(omega^(j))
        let p = params(4, 2, 1);
        let f = poly(4, 3);
        let e0 = encode(&p, &f);
        for (omega, &val) in e0.iter().enumerate() {
            let r: Vec<Fe3> = (1..=p.n)
                .map(|j| {
                    let g = gate(&p.seed, j, omega >> j);
                    Fe3::from_base(if (omega >> (j - 1)) & 1 == 0 { g.t0 } else { g.t1 })
                })
                .collect();
            assert_eq!(Fe3::from_base(val), eval_multilinear(&f, &r));
        }
    }

    #[test]
    fn wrong_value_rejected() {
        let p = params(6, 2, 40);
        let (root, c) = commit(&p, &poly(6, 1));
        let (_, _, mut proof) = prove(&p, &c);
        let fake = proof.last[0].add(Fe3::ONE);
        for e in proof.last.iter_mut() {
            *e = fake;
        }
        assert!(verify(&p, &root, &proof).is_err());
    }

    #[test]
    fn corrupted_table_folded_honestly_rejected() {
        let p = params(6, 2, 40);
        let f = poly(6, 1);
        let mut e0 = encode(&p, &f);
        for i in (0..e0.len()).step_by(3) {
            e0[i] = e0[i].add(Fp::ONE);
        }
        let tree = MerkleTree::new(&base_leaves(&e0));
        let (_, _, proof) = prove_inner(&p, &e0, &tree, &e0);
        assert!(verify(&p, &tree.root(), &proof).is_err());
    }

    #[test]
    fn corrupted_table_with_true_folds_rejected() {
        // commit to a corrupted table but fold the true codeword: layer-1 checks must catch it
        let p = params(8, 2, 60);
        let f = poly(8, 9);
        let honest = encode(&p, &f);
        let mut bad = honest.clone();
        for i in (0..bad.len()).step_by(4) {
            bad[i] = bad[i].add(Fp::new(5));
        }
        let tree = MerkleTree::new(&base_leaves(&bad));
        let (_, _, proof) = prove_inner(&p, &bad, &tree, &honest);
        let err = verify(&p, &tree.root(), &proof).unwrap_err();
        assert!(err.contains("gate check failed at layer 1"), "{err}");
    }
}

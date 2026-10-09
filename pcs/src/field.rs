#![allow(clippy::should_implement_trait)]
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Goldilocks field F_p, p = 2^64 - 2^32 + 1, and its cubic extension F_p[x]/(x^3 - W).

use std::sync::OnceLock;

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
const EPSILON: u64 = 0xFFFF_FFFF; // 2^64 mod p

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fp(pub u64);

#[inline]
fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & EPSILON;
    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        t0 = t0.wrapping_sub(EPSILON);
    }
    let t1 = x_hi_lo * EPSILON;
    let (res, carry) = t0.overflowing_add(t1);
    let res = res.wrapping_add(EPSILON * carry as u64);
    if res >= P { res - P } else { res }
}

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    #[inline]
    pub fn new(x: u64) -> Fp {
        Fp(if x >= P { x - P } else { x })
    }
    #[inline]
    pub fn add(self, o: Fp) -> Fp {
        let s = self.0 as u128 + o.0 as u128;
        Fp(if s >= P as u128 {
            (s - P as u128) as u64
        } else {
            s as u64
        })
    }
    #[inline]
    pub fn sub(self, o: Fp) -> Fp {
        Fp(if self.0 >= o.0 {
            self.0 - o.0
        } else {
            self.0.wrapping_sub(o.0).wrapping_add(P)
        })
    }
    #[inline]
    pub fn neg(self) -> Fp {
        Fp::ZERO.sub(self)
    }
    #[inline]
    pub fn mul(self, o: Fp) -> Fp {
        Fp(reduce128(self.0 as u128 * o.0 as u128))
    }
    pub fn pow(self, mut e: u64) -> Fp {
        let (mut b, mut r) = (self, Fp::ONE);
        while e > 0 {
            if e & 1 == 1 {
                r = r.mul(b);
            }
            b = b.mul(b);
            e >>= 1;
        }
        r
    }
    pub fn inv(self) -> Fp {
        assert!(self.0 != 0, "inverse of zero");
        self.pow(P - 2)
    }
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

/// Montgomery batch inversion (all inputs nonzero).
pub fn batch_inverse(xs: &[Fp]) -> Vec<Fp> {
    let mut acc = Vec::with_capacity(xs.len());
    let mut prod = Fp::ONE;
    for &x in xs {
        acc.push(prod);
        prod = prod.mul(x);
    }
    let mut inv = prod.inv();
    let mut out = vec![Fp::ZERO; xs.len()];
    for i in (0..xs.len()).rev() {
        out[i] = acc[i].mul(inv);
        inv = inv.mul(xs[i]);
    }
    out
}

/// Non-residue W: x^3 - W is irreducible iff W is not a cube (3 | p - 1).
pub const W: Fp = Fp(7);

fn zeta() -> (Fp, Fp) {
    static Z: OnceLock<(Fp, Fp)> = OnceLock::new();
    *Z.get_or_init(|| {
        let z = W.pow((P - 1) / 3);
        (z, z.mul(z))
    })
}

/// Element a0 + a1 x + a2 x^2 of F_p[x]/(x^3 - W).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fe3(pub [Fp; 3]);

impl Fe3 {
    pub const ZERO: Fe3 = Fe3([Fp::ZERO; 3]);
    pub const ONE: Fe3 = Fe3([Fp::ONE, Fp::ZERO, Fp::ZERO]);

    pub fn from_base(a: Fp) -> Fe3 {
        Fe3([a, Fp::ZERO, Fp::ZERO])
    }
    #[inline]
    pub fn add(self, o: Fe3) -> Fe3 {
        Fe3([
            self.0[0].add(o.0[0]),
            self.0[1].add(o.0[1]),
            self.0[2].add(o.0[2]),
        ])
    }
    #[inline]
    pub fn sub(self, o: Fe3) -> Fe3 {
        Fe3([
            self.0[0].sub(o.0[0]),
            self.0[1].sub(o.0[1]),
            self.0[2].sub(o.0[2]),
        ])
    }
    #[inline]
    pub fn mul_base(self, s: Fp) -> Fe3 {
        Fe3([self.0[0].mul(s), self.0[1].mul(s), self.0[2].mul(s)])
    }
    #[inline]
    pub fn mul(self, o: Fe3) -> Fe3 {
        let [a0, a1, a2] = self.0;
        let [b0, b1, b2] = o.0;
        let r0 = a0.mul(b0).add(W.mul(a1.mul(b2).add(a2.mul(b1))));
        let r1 = a0.mul(b1).add(a1.mul(b0)).add(W.mul(a2.mul(b2)));
        let r2 = a0.mul(b2).add(a1.mul(b1)).add(a2.mul(b0));
        Fe3([r0, r1, r2])
    }
    fn frob(self) -> Fe3 {
        let (z, z2) = zeta();
        Fe3([self.0[0], self.0[1].mul(z), self.0[2].mul(z2)])
    }
    fn frob2(self) -> Fe3 {
        let (z, z2) = zeta();
        Fe3([self.0[0], self.0[1].mul(z2), self.0[2].mul(z)])
    }
    pub fn inv(self) -> Fe3 {
        let c = self.frob().mul(self.frob2());
        let norm = self.mul(c).0[0];
        c.mul_base(norm.inv())
    }
    pub fn to_bytes(self) -> [u8; 24] {
        let mut b = [0u8; 24];
        for i in 0..3 {
            b[8 * i..8 * i + 8].copy_from_slice(&self.0[i].to_bytes());
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_matches_u128() {
        let mut x = 0x1234_5678_9abc_def0u64;
        for _ in 0..10_000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = Fp::new(x);
            let b = Fp::new(x.rotate_left(17) ^ 0xdead_beef);
            let expect = ((a.0 as u128 * b.0 as u128) % P as u128) as u64;
            assert_eq!(a.mul(b).0, expect);
            assert_eq!(a.mul(a.inv()), Fp::ONE);
        }
    }

    #[test]
    fn w_is_not_a_cube() {
        assert_ne!(W.pow((P - 1) / 3), Fp::ONE);
    }

    #[test]
    fn ext_inverse() {
        let a = Fe3([Fp::new(3), Fp::new(5), Fp::new(11)]);
        assert_eq!(a.mul(a.inv()), Fe3::ONE);
        let b = Fe3([Fp::new(u64::MAX), Fp::new(1 << 40), Fp::new(77)]);
        assert_eq!(b.mul(b.inv()), Fe3::ONE);
    }

    #[test]
    fn batch_inverse_ok() {
        let xs: Vec<Fp> = (1..100u64).map(|i| Fp::new(i * 7919)).collect();
        let inv = batch_inverse(&xs);
        for (x, y) in xs.iter().zip(inv.iter()) {
            assert_eq!(x.mul(*y), Fp::ONE);
        }
    }
}

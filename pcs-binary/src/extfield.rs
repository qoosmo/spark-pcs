#![allow(clippy::suspicious_arithmetic_impl, clippy::suspicious_op_assign_impl)]

use crate::field::F128;
use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// GF(2^256) = GF(2^128)[y] / (y^2 + y + alpha), alpha=x^121.
/// trace(alpha)=1, hence the quadratic is irreducible.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct F256 {
    pub c0: F128,
    pub c1: F128,
}

impl F256 {
    pub const ZERO: Self = Self {
        c0: F128::ZERO,
        c1: F128::ZERO,
    };
    pub const ONE: Self = Self {
        c0: F128::ONE,
        c1: F128::ZERO,
    };
    pub const ALPHA: F128 = F128(1u128 << 121);

    #[inline(always)]
    pub fn from_base(x: F128) -> Self {
        Self {
            c0: x,
            c1: F128::ZERO,
        }
    }

    #[inline]
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&bytes[..16]);
        b.copy_from_slice(&bytes[16..]);
        Self {
            c0: F128(u128::from_le_bytes(a)),
            c1: F128(u128::from_le_bytes(b)),
        }
    }

    #[inline]
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.c0.to_le_bytes());
        out[16..].copy_from_slice(&self.c1.to_le_bytes());
        out
    }

    /// Mixed extension/base multiplication: exactly two base-field multiplications.
    #[inline(always)]
    pub fn mul_base(self, rhs: F128) -> Self {
        Self {
            c0: self.c0 * rhs,
            c1: self.c1 * rhs,
        }
    }

    /// Karatsuba tower multiplication. Three general F128 multiplications;
    /// multiplication by alpha=x^121 is a fixed linear shift/reduction map.
    #[inline(always)]
    fn mul_impl(self, rhs: Self) -> Self {
        let m0 = self.c0 * rhs.c0;
        let m1 = self.c1 * rhs.c1;
        let m2 = (self.c0 + self.c1) * (rhs.c0 + rhs.c1);
        // y^2 = y + alpha.  ad+bc+bd = m2+m0 in characteristic two.
        Self {
            c0: m0 + m1.mul_x121(),
            c1: m2 + m0,
        }
    }
}

impl Add for F256 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}
impl AddAssign for F256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.c0 += rhs.c0;
        self.c1 += rhs.c1;
    }
}
impl Sub for F256 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}
impl SubAssign for F256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}
impl Mul for F256 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(rhs)
    }
}
impl MulAssign for F256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl fmt::Debug for F256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:032x}{:032x}", self.c1.0, self.c0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn tower_polynomial_is_irreducible() {
        assert_eq!(F256::ALPHA.trace_bit(), 1);
    }

    #[test]
    fn mixed_matches_full_embedding() {
        let mut rng = StdRng::seed_from_u64(77);
        for _ in 0..1000 {
            let a = F256 {
                c0: F128::random(&mut rng),
                c1: F128::random(&mut rng),
            };
            let b = F128::random(&mut rng);
            assert_eq!(a.mul_base(b), a * F256::from_base(b));
        }
    }

    #[test]
    fn multiplication_basic_laws() {
        let mut rng = StdRng::seed_from_u64(91);
        for _ in 0..1000 {
            let a = F256 {
                c0: F128::random(&mut rng),
                c1: F128::random(&mut rng),
            };
            let b = F256 {
                c0: F128::random(&mut rng),
                c1: F128::random(&mut rng),
            };
            let c = F256 {
                c0: F128::random(&mut rng),
                c1: F128::random(&mut rng),
            };
            assert_eq!(a * F256::ONE, a);
            assert_eq!(a * b, b * a);
            assert_eq!((a * b) * c, a * (b * c));
        }
    }
}

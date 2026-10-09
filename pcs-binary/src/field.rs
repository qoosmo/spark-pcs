#![allow(clippy::suspicious_arithmetic_impl, clippy::suspicious_op_assign_impl)]

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand::RngCore;

/// GF(2^128) with modulus x^128 + x^7 + x^2 + x + 1.
///
/// On AArch64 builds with the AES/PMULL feature enabled (Apple M1 included),
/// multiplication uses three 64x64 PMULL operations (Karatsuba) followed by
/// reduction modulo the GCM polynomial. Other targets retain the portable
/// constant-shape reference multiplier.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct F128(pub u128);

impl F128 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    #[allow(dead_code)]
    const REDUCTION: u128 = 0x87; // x^7 + x^2 + x + 1

    #[inline]
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        Self(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128)
    }

    #[inline]
    pub fn square(self) -> Self {
        self * self
    }

    pub fn pow(self, mut e: u128) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while e != 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            e >>= 1;
            if e != 0 {
                base = base.square();
            }
        }
        acc
    }

    /// a^(2^128-2)
    pub fn inv(self) -> Self {
        assert!(self != Self::ZERO, "inverse of zero");
        self.pow(u128::MAX - 1)
    }

    #[inline]
    pub fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Multiply by x^121 in GF(2^128). This is the tower constant alpha.
    /// The unreduced carryless product is just a 121-bit shift.
    #[inline(always)]
    pub fn mul_x121(self) -> Self {
        let lo = self.0 << 121;
        let hi = self.0 >> 7;
        Self(Self::reduce_256(lo, hi))
    }

    /// Absolute trace GF(2^128) -> GF(2).
    pub fn trace_bit(self) -> u8 {
        let mut t = self;
        let mut x = self;
        for _ in 1..128 {
            x = x.square();
            t += x;
        }
        debug_assert!(t == Self::ZERO || t == Self::ONE);
        (t.0 & 1) as u8
    }

    #[inline]
    #[allow(dead_code)]
    fn mul_portable(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut z = 0u128;
        for _ in 0..128 {
            let mask = 0u128.wrapping_sub(b & 1);
            z ^= a & mask;
            b >>= 1;
            let carry = a >> 127;
            a <<= 1;
            a ^= Self::REDUCTION & 0u128.wrapping_sub(carry);
        }
        Self(z)
    }

    /// Reduce a 256-bit carryless product (lo + hi*x^128) modulo
    /// x^128 + x^7 + x^2 + x + 1.
    #[inline(always)]
    fn reduce_256(mut lo: u128, hi: u128) -> u128 {
        // x^128 = x^7 + x^2 + x + 1.
        lo ^= hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);

        // Bits that overflowed those shifts represent e*x^128.  Since the
        // largest shift is 7, e has degree < 7; one more substitution finishes.
        let e = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
        lo ^= e ^ (e << 1) ^ (e << 2) ^ (e << 7);
        lo
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[target_feature(enable = "aes,neon")]
    unsafe fn mul_pmull(self, rhs: Self) -> Self {
        use core::arch::aarch64::vmull_p64;

        let a0 = self.0 as u64;
        let a1 = (self.0 >> 64) as u64;
        let b0 = rhs.0 as u64;
        let b1 = (rhs.0 >> 64) as u64;

        // Karatsuba: three polynomial 64x64 -> 128 multiplies.
        let p00 = vmull_p64(a0, b0);
        let p11 = vmull_p64(a1, b1);
        let pm = vmull_p64(a0 ^ a1, b0 ^ b1);
        let cross = pm ^ p00 ^ p11;

        let lo = p00 ^ (cross << 64);
        let hi = p11 ^ (cross >> 64);
        Self(Self::reduce_256(lo, hi))
    }

    #[inline(always)]
    fn mul_impl(self, rhs: Self) -> Self {
        #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
        {
            unsafe { self.mul_pmull(rhs) }
        }
        #[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
        {
            self.mul_portable(rhs)
        }
    }
}

/// Batch inversion with one field inversion and O(n) multiplications.
/// Inputs must all be nonzero.
pub fn batch_inverse(values: &[F128]) -> Vec<F128> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut prefix = Vec::with_capacity(values.len());
    let mut acc = F128::ONE;
    for &x in values {
        assert!(x != F128::ZERO, "batch inverse contains zero");
        prefix.push(acc);
        acc *= x;
    }
    let mut inv_acc = acc.inv();
    let mut out = vec![F128::ZERO; values.len()];
    for i in (0..values.len()).rev() {
        out[i] = inv_acc * prefix[i];
        inv_acc *= values[i];
    }
    out
}

impl Add for F128 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl AddAssign for F128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl Sub for F128 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}
impl SubAssign for F128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl Mul for F128 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(rhs)
    }
}
impl MulAssign for F128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl fmt::Debug for F128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:032x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn field_basics() {
        let a = F128(0x1234);
        assert_eq!(a + a, F128::ZERO);
        assert_eq!(a * F128::ONE, a);
        assert_eq!(a * F128::ZERO, F128::ZERO);
        let b = F128(0xdeadbeef);
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn inverse_works() {
        let a = F128(0x123456789abcdef0fedcba9876543211);
        assert_eq!(a * a.inv(), F128::ONE);
    }

    #[test]
    fn fast_mul_matches_portable_reference() {
        let mut rng = StdRng::seed_from_u64(0x51a2_cafe);
        for _ in 0..10_000 {
            let a = F128::random(&mut rng);
            let b = F128::random(&mut rng);
            assert_eq!(a * b, a.mul_portable(b));
        }
    }

    #[test]
    fn batch_inverse_works() {
        let mut rng = StdRng::seed_from_u64(9);
        let xs = (0..257)
            .map(|_| {
                let mut x = F128::random(&mut rng);
                while x == F128::ZERO {
                    x = F128::random(&mut rng);
                }
                x
            })
            .collect::<Vec<_>>();
        let invs = batch_inverse(&xs);
        assert_eq!(xs.len(), invs.len());
        for (&x, &ix) in xs.iter().zip(&invs) {
            assert_eq!(x * ix, F128::ONE);
        }
    }
}

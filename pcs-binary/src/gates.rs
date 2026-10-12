// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::field::F128;

#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub t0: F128,
    pub t1: F128,
    /// Compatibility field. Under `tplus1` this is always ONE.
    pub inv_dt: F128,
}

impl Gate {
    #[inline]
    pub fn new(t0: F128, t1: F128, inv_dt: F128) -> Self {
        debug_assert!(t0 != t1);
        #[cfg(feature = "tplus1")]
        {
            debug_assert_eq!(t1, t0 + F128::ONE);
            debug_assert_eq!(inv_dt, F128::ONE);
        }
        #[cfg(not(feature = "tplus1"))]
        debug_assert_eq!((t1 + t0) * inv_dt, F128::ONE);
        Self { t0, t1, inv_dt }
    }

    #[inline(always)]
    pub fn encode_pair(self, u: F128, v: F128) -> (F128, F128) {
        #[cfg(feature = "tplus1")]
        {
            let a = u + self.t0 * v;
            return (a, a + v);
        }
        #[cfg(not(feature = "tplus1"))]
        {
            (u + self.t0 * v, u + self.t1 * v)
        }
    }

    #[inline(always)]
    pub fn fold_pair(self, w0: F128, w1: F128, z: F128) -> F128 {
        #[cfg(feature = "tplus1")]
        {
            return w0 + (z + self.t0) * (w1 + w0);
        }
        #[cfg(not(feature = "tplus1"))]
        {
            let lambda = (z + self.t0) * self.inv_dt;
            w0 + lambda * (w1 + w0)
        }
    }

    #[inline(always)]
    pub fn fold_pair_with_lambda(w0: F128, w1: F128, lambda: F128) -> F128 {
        w0 + lambda * (w1 + w0)
    }

    #[inline(always)]
    pub fn lambda(self, z: F128) -> F128 {
        #[cfg(feature = "tplus1")]
        {
            return z + self.t0;
        }
        #[cfg(not(feature = "tplus1"))]
        {
            (z + self.t0) * self.inv_dt
        }
    }
}

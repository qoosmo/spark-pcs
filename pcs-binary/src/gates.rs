use crate::field::F128;

#[derive(Clone, Copy, Debug)]
pub struct Gate {
    pub t0: F128,
    pub t1: F128,
    /// Setup-only precomputation: 1/(t1+t0).
    pub inv_dt: F128,
}

impl Gate {
    #[inline]
    pub fn new(t0: F128, t1: F128, inv_dt: F128) -> Self {
        debug_assert!(t0 != t1);
        debug_assert_eq!((t1 + t0) * inv_dt, F128::ONE);
        Self { t0, t1, inv_dt }
    }

    #[inline(always)]
    pub fn encode_pair(self, u: F128, v: F128) -> (F128, F128) {
        (u + self.t0 * v, u + self.t1 * v)
    }

    /// Characteristic-two fold:
    /// lambda=(z+t0)/(t1+t0), y=w0+lambda(w1+w0).
    #[inline(always)]
    pub fn fold_pair(self, w0: F128, w1: F128, z: F128) -> F128 {
        let lambda = (z + self.t0) * self.inv_dt;
        w0 + lambda * (w1 + w0)
    }

    #[inline(always)]
    pub fn fold_pair_with_lambda(w0: F128, w1: F128, lambda: F128) -> F128 {
        w0 + lambda * (w1 + w0)
    }

    #[inline(always)]
    pub fn lambda(self, z: F128) -> F128 {
        (z + self.t0) * self.inv_dt
    }
}

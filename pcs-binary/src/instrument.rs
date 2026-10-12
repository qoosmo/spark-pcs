use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub const NONE: usize = 0;
pub const ENCODE: usize = 1;
pub const COMMIT: usize = 2;
pub const FOLD: usize = 3;
pub const VERIFY: usize = 4;
const N: usize = 5;

static PHASE: AtomicUsize = AtomicUsize::new(NONE);
static MUL: [AtomicU64; N] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static INV: [AtomicU64; N] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static HASH: [AtomicU64; N] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub mul: u64,
    pub inv: u64,
    pub hash: u64,
}

#[inline(always)]
pub fn set_phase(p: usize) {
    PHASE.store(p, Ordering::Relaxed);
}
#[inline(always)]
fn phase() -> usize {
    PHASE.load(Ordering::Relaxed).min(N - 1)
}
#[inline(always)]
pub fn inc_mul() {
    MUL[phase()].fetch_add(1, Ordering::Relaxed);
}
#[inline(always)]
pub fn inc_inv() {
    INV[phase()].fetch_add(1, Ordering::Relaxed);
}
#[inline(always)]
pub fn inc_hash() {
    HASH[phase()].fetch_add(1, Ordering::Relaxed);
}

pub fn reset() {
    for i in 0..N {
        MUL[i].store(0, Ordering::Relaxed);
        INV[i].store(0, Ordering::Relaxed);
        HASH[i].store(0, Ordering::Relaxed);
    }
    set_phase(NONE);
}
pub fn get(p: usize) -> Counts {
    Counts {
        mul: MUL[p].load(Ordering::Relaxed),
        inv: INV[p].load(Ordering::Relaxed),
        hash: HASH[p].load(Ordering::Relaxed),
    }
}

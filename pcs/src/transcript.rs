//! Fiat-Shamir transcript (SHA-256 sponge-style chaining).

use crate::field::{Fe3, Fp, P};
use sha2::{Digest, Sha256};

pub struct Transcript {
    state: [u8; 32],
    counter: u64,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut t = Transcript { state: [0u8; 32], counter: 0 };
        t.absorb(label);
        t
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        self.state = h.finalize().into();
        self.counter = 0;
    }

    fn next_u64(&mut self) -> u64 {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update(b"squeeze");
        h.update(self.counter.to_le_bytes());
        self.counter += 1;
        let d: [u8; 32] = h.finalize().into();
        u64::from_le_bytes(d[..8].try_into().unwrap())
    }

    fn squeeze_fp(&mut self) -> Fp {
        loop {
            let x = self.next_u64();
            if x < P {
                return Fp(x);
            }
        }
    }

    pub fn squeeze_ext(&mut self) -> Fe3 {
        let e = Fe3([self.squeeze_fp(), self.squeeze_fp(), self.squeeze_fp()]);
        self.absorb(&e.to_bytes());
        e
    }

    /// Uniform index in [0, 2^bits).
    pub fn squeeze_index(&mut self, bits: usize) -> usize {
        (self.next_u64() & ((1u64 << bits) - 1)) as usize
    }
}

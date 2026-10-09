// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical Fiat--Shamir header for SPARK v0.9.
//!
//! This module changes transcript initialization only. It does not change
//! `SPARK-GATE-v0.7`, the gate seed consumed by gate derivation, the encoding,
//! folding equations, Merkle layout, or the query sampling rule.
//!
//! Canonical binding order for v0.9:
//! 1. canonical header;
//! 2. initial Merkle root;
//! 3. at each folding level, the scheduled committed root if one exists,
//!    followed by the next fold challenge;
//! 4. the complete last layer (one value for a single proof, all `t` values
//!    for a batch proof);
//! 5. the grinding nonce, after checking its `g`-bit predicate;
//! 6. query positions derived from the resulting transcript.
//!
//! The implementation's public gate seed is currently a `u64`. The v0.9
//! transcript binds it in the required fixed 32-byte header field as
//! `seed.to_le_bytes() || 24 zero bytes`. This injective representation leaves
//! `SPARK-GATE-v0.7` unchanged.

use crate::extfield::F256;
use crate::merkle_v05::HashKind;
use crate::security::{soundness_bits_from, SecurityReport};

pub const FS_DOMAIN_V09: &[u8] = b"SPARK-FS-v0.9";
pub const GATE_DOMAIN_V07: &[u8] = b"SPARK-GATE-v0.7";
pub const PROOF_FORMAT_VERSION_V09: u8 = 9;
pub const HASH_ID_BLAKE3: u8 = 1;
pub const HASH_ID_SHA256: u8 = 2;
pub const FIELD_ID_F128: u8 = 1;
pub const FIELD_ID_K256_TOWER: u8 = 1;

#[derive(Clone, Debug)]
pub struct ParamsV09 {
    pub n: usize,
    pub k: usize,
    pub i0: usize,
    pub s: usize,
    pub g: u32,
    pub t: usize,
    pub commit_every: usize,
    pub gate_seed: u64,
    pub setup_counter: u64,
    pub hash_kind: HashKind,
    pub target_bits: u32,
}

impl ParamsV09 {
    pub fn schedule(&self) -> Vec<u32> {
        committed_schedule(self.n, self.commit_every)
    }

    pub fn header(&self) -> Result<TranscriptHeaderV09, String> {
        TranscriptHeaderV09::from_params(self)
    }

    pub fn validate(&self) -> Result<SecurityReport, String> {
        if self.n == 0 {
            return Err("n must be nonzero".into());
        }
        if self.i0 == 0 || self.i0 > self.n {
            return Err("i0 must satisfy 1 <= i0 <= n".into());
        }
        if self.s == 0 {
            return Err("s must be nonzero".into());
        }
        if self.t == 0 {
            return Err("batch size t must be nonzero".into());
        }
        if self.commit_every == 0 || self.commit_every > self.n {
            return Err("commit_every must satisfy 1 <= commit_every <= n".into());
        }
        if self.g > 32 {
            return Err("grinding bits g must be <= 32".into());
        }
        if self.target_bits < 128 {
            return Err("target_bits must be at least 128".into());
        }

        let report = soundness_bits_from(
            self.n,
            self.k,
            128.0,
            256.0,
            self.g as f64,
            (self.target_bits - 128) as f64,
            self.i0,
        );

        if self.s < report.s {
            return Err(format!(
                "insufficient query count: s={} but verifier requires at least {}",
                self.s, report.s
            ));
        }
        if report.fold_bits + 1e-9 < self.target_bits as f64 {
            return Err(format!(
                "fold term {:.6} bits is below target {} bits",
                report.fold_bits, self.target_bits
            ));
        }
        Ok(report)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptHeaderV09 {
    pub proof_format_version: u8,
    pub hash_id: u8,
    pub field_id_f: u8,
    pub field_id_k: u8,
    pub alpha: [u8; 16],
    pub n: u32,
    pub k: u32,
    pub i0: u32,
    pub s: u32,
    pub g: u32,
    pub t: u32,
    pub schedule: Vec<u32>,
    pub gate_seed: [u8; 32],
    pub setup_counter: u64,
}

impl TranscriptHeaderV09 {
    pub fn from_params(p: &ParamsV09) -> Result<Self, String> {
        let n = u32::try_from(p.n).map_err(|_| "n does not fit in u32")?;
        let k = u32::try_from(p.k).map_err(|_| "k does not fit in u32")?;
        let i0 = u32::try_from(p.i0).map_err(|_| "i0 does not fit in u32")?;
        let s = u32::try_from(p.s).map_err(|_| "s does not fit in u32")?;
        let t = u32::try_from(p.t).map_err(|_| "t does not fit in u32")?;

        let hash_id = match p.hash_kind {
            HashKind::Blake3 => HASH_ID_BLAKE3,
            HashKind::Sha256 => HASH_ID_SHA256,
        };

        let mut gate_seed = [0u8; 32];
        gate_seed[..8].copy_from_slice(&p.gate_seed.to_le_bytes());

        Ok(Self {
            proof_format_version: PROOF_FORMAT_VERSION_V09,
            hash_id,
            field_id_f: FIELD_ID_F128,
            field_id_k: FIELD_ID_K256_TOWER,
            alpha: F256::ALPHA.to_le_bytes(),
            n,
            k,
            i0,
            s,
            g: p.g,
            t,
            schedule: p.schedule(),
            gate_seed,
            setup_counter: p.setup_counter,
        })
    }

    /// Exact byte layout:
    ///
    /// lp("SPARK-FS-v0.9")
    /// proof_format_version : u8
    /// hash_id              : u8
    /// field_id_F           : u8
    /// field_id_K           : u8
    /// alpha                : [u8;16]
    /// n                    : u32 LE
    /// k                    : u32 LE
    /// i0                   : u32 LE
    /// s                    : u32 LE
    /// g                    : u32 LE
    /// t                    : u32 LE
    /// schedule_len         : u32 LE
    /// schedule[i]          : u32 LE
    /// gate_seed            : [u8;32]
    /// setup_counter        : u64 LE
    /// lp("SPARK-GATE-v0.7")
    ///
    /// lp(x) = len(x):u32 LE || x.
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_with_domains(FS_DOMAIN_V09, GATE_DOMAIN_V07)
    }

    pub(crate) fn serialize_with_domains(&self, fs_domain: &[u8], gate_domain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + 4 * self.schedule.len());
        put_lp(&mut out, fs_domain);
        out.push(self.proof_format_version);
        out.push(self.hash_id);
        out.push(self.field_id_f);
        out.push(self.field_id_k);
        out.extend_from_slice(&self.alpha);
        out.extend_from_slice(&self.n.to_le_bytes());
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.i0.to_le_bytes());
        out.extend_from_slice(&self.s.to_le_bytes());
        out.extend_from_slice(&self.g.to_le_bytes());
        out.extend_from_slice(&self.t.to_le_bytes());
        out.extend_from_slice(&(self.schedule.len() as u32).to_le_bytes());
        for level in &self.schedule {
            out.extend_from_slice(&level.to_le_bytes());
        }
        out.extend_from_slice(&self.gate_seed);
        out.extend_from_slice(&self.setup_counter.to_le_bytes());
        put_lp(&mut out, gate_domain);
        out
    }
}

pub fn committed_schedule(n: usize, commit_every: usize) -> Vec<u32> {
    if commit_every == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut level = commit_every;
    while level < n {
        out.push(level as u32);
        level += commit_every;
    }
    out
}

fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("domain string too long");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

use rayon::prelude::*;
use sha2::{Digest, Sha256};

fn hash_parts_v09(kind: HashKind, parts: &[&[u8]]) -> [u8; 32] {
    match kind {
        HashKind::Blake3 => {
            let mut h = blake3::Hasher::new();
            for p in parts {
                h.update(p);
            }
            *h.finalize().as_bytes()
        }
        HashKind::Sha256 => {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().into()
        }
    }
}

/// Canonical v0.9 transcript start: header first, then the initial root.
pub fn initial_state_v09(header: &TranscriptHeaderV09, commitment: &[u8; 32]) -> Vec<u8> {
    let mut st = header.serialize();
    st.extend_from_slice(commitment);
    st
}

pub fn challenge_field_v09(state: &[u8], label: &[u8], counter: u64, kind: HashKind) -> F256 {
    F256::from_le_bytes(hash_parts_v09(
        kind,
        &[
            b"SPARK-FS-CHALLENGE-v0.9",
            label,
            &counter.to_le_bytes(),
            state,
        ],
    ))
}

pub fn challenge_index_v09(state: &[u8], counter: u64, modulus: usize, kind: HashKind) -> usize {
    let d = hash_parts_v09(kind, &[b"SPARK-QUERY-v0.9", &counter.to_le_bytes(), state]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    (u64::from_le_bytes(b) as usize) % modulus
}

pub fn append_single_last_v09(state: &mut Vec<u8>, eval: F256) {
    state.extend_from_slice(b"SPARK-LAST-v0.9");
    state.extend_from_slice(&eval.to_le_bytes());
}

pub fn append_batch_last_v09(state: &mut Vec<u8>, evals: &[F256]) {
    state.extend_from_slice(b"SPARK-BATCH-LAST-v0.9");
    state.extend_from_slice(&(evals.len() as u32).to_le_bytes());
    for e in evals {
        state.extend_from_slice(&e.to_le_bytes());
    }
}

fn leading_zero_bits_v09(d: &[u8; 32]) -> u32 {
    let mut z = 0u32;
    for &b in d {
        if b == 0 {
            z += 8;
        } else {
            z += b.leading_zeros();
            break;
        }
    }
    z
}

pub fn grind_seed_v09(state_with_last: &[u8], kind: HashKind) -> [u8; 32] {
    hash_parts_v09(kind, &[b"SPARK-GRIND-SEED-v0.9", state_with_last])
}

pub fn valid_grind_nonce_v09(seed: &[u8; 32], nonce: u64, bits: u32, kind: HashKind) -> bool {
    if bits == 0 {
        return nonce == 0;
    }
    let d = hash_parts_v09(kind, &[b"SPARK-GRIND-v0.9", seed, &nonce.to_le_bytes()]);
    leading_zero_bits_v09(&d) >= bits
}

pub fn find_grind_nonce_v09(seed: &[u8; 32], bits: u32, kind: HashKind) -> u64 {
    assert!(bits <= 32);
    if bits == 0 {
        return 0;
    }
    const CHUNK: u64 = 1 << 16;
    let mut start = 0u64;
    loop {
        let end = start.checked_add(CHUNK).expect("grinding nonce overflow");
        if let Some(nonce) = (start..end)
            .into_par_iter()
            .filter(|&n| valid_grind_nonce_v09(seed, n, bits, kind))
            .min()
        {
            return nonce;
        }
        start = end;
    }
}

pub fn append_nonce_v09(state: &mut Vec<u8>, nonce: Option<u64>) {
    if let Some(n) = nonce {
        state.extend_from_slice(b"SPARK-GRIND-NONCE-v0.9");
        state.extend_from_slice(&n.to_le_bytes());
    }
}

pub fn derive_queries_v09(
    state_after_last: &[u8],
    nonce: Option<u64>,
    s: usize,
    leaves: usize,
    kind: HashKind,
) -> Vec<usize> {
    let mut st = state_after_last.to_vec();
    append_nonce_v09(&mut st, nonce);
    (0..s)
        .map(|i| challenge_index_v09(&st, i as u64, leaves, kind))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ParamsV09 {
        ParamsV09 {
            n: 20,
            k: 2,
            i0: 3,
            s: 407,
            g: 16,
            t: 1,
            commit_every: 3,
            gate_seed: 12345,
            setup_counter: 7,
            hash_kind: HashKind::Blake3,
            target_bits: 192,
        }
    }

    #[test]
    fn v09_n20_params_validate_and_recompute_s() {
        let p = params();
        let r = p.validate().unwrap();
        assert_eq!(r.s, 407);
        assert!(r.fold_bits >= 192.0);
    }

    #[test]
    fn verifier_rejects_too_small_s() {
        let mut p = params();
        p.s = 406;
        let e = p.validate().unwrap_err();
        assert!(e.contains("requires at least 407"), "{e}");
    }

    #[test]
    fn alpha_is_x121_in_little_endian_header() {
        let h = params().header().unwrap();
        assert_eq!(h.alpha, (1u128 << 121).to_le_bytes());
    }

    #[test]
    fn gate_seed_u64_has_injective_32_byte_canonical_encoding() {
        let h = params().header().unwrap();
        assert_eq!(&h.gate_seed[..8], &12345u64.to_le_bytes());
        assert!(h.gate_seed[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn schedule_is_explicit_committed_level_list() {
        assert_eq!(params().schedule(), vec![3, 6, 9, 12, 15, 18]);
    }

    #[test]
    fn canonical_header_distinguishes_every_bound_field() {
        let base = params();
        let base_bytes = base.header().unwrap().serialize();

        macro_rules! differs {
            ($mutator:expr) => {{
                let mut p = params();
                $mutator(&mut p);
                assert_ne!(base_bytes, p.header().unwrap().serialize());
            }};
        }

        differs!(|p: &mut ParamsV09| p.n = 19);
        differs!(|p: &mut ParamsV09| p.k = 3);
        differs!(|p: &mut ParamsV09| p.i0 = 2);
        differs!(|p: &mut ParamsV09| p.s = 408);
        differs!(|p: &mut ParamsV09| p.g = 15);
        differs!(|p: &mut ParamsV09| p.t = 4);
        differs!(|p: &mut ParamsV09| p.commit_every = 4);
        differs!(|p: &mut ParamsV09| p.gate_seed ^= 1);
        differs!(|p: &mut ParamsV09| p.setup_counter ^= 1);
        differs!(|p: &mut ParamsV09| p.hash_kind = HashKind::Sha256);

        let mut h = base.header().unwrap();
        h.proof_format_version ^= 1;
        assert_ne!(base_bytes, h.serialize());

        let h = base.header().unwrap();
        assert_ne!(
            base_bytes,
            h.serialize_with_domains(b"SPARK-FS-v0.9-test", GATE_DOMAIN_V07)
        );
        assert_ne!(
            base_bytes,
            h.serialize_with_domains(FS_DOMAIN_V09, b"SPARK-GATE-v0.7-test")
        );
    }

    #[test]
    fn serialization_is_deterministic() {
        let h = params().header().unwrap();
        assert_eq!(h.serialize(), h.serialize());
    }
}

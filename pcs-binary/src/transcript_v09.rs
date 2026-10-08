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

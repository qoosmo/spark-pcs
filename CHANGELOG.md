<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Changelog

## v0.10-rc1 - 2026-10-12

- `(t,t+1)` is the default gate family. Reproduce v0.9 gates with
  `--no-default-features --features legacy-gates`.
- New `SPARK-FS-v0.10`, `SPARK-SEED-v0.10-tplus1`, and
  `SPARK-GATE-v0.10-tplus1` domains; proof-format version 10.
- Public gate seed `0x50643f649c978b38`; checked setup counter `0`.
- Theorem 3.19 is unchanged: double-parent constraints are deterministic,
  singleton constraints retain probability `1/q`, and parent samples remain independent.
- At `n=20,k=2,i0=3,s=407`: prover median `-17.4%` with one thread and
  `-14.5%` with eight Rayon threads on Apple M1.
- Exact instrumentation: encode multiplications `83,886,080 -> 41,943,040`;
  folding removes `8,388,600` base-field multiplications; commitment remains
  exactly `4,793,481` Merkle hashes.
- Deterministic v0.10 proof size `594,218` bytes. Pre-dedup opening structure is
  unchanged; the `+0.548%` size difference versus v0.9 is due to the v0.10 domain-separated query positions and Merkle-path deduplication.
- The withdrawn `1.73x / -42%` figure must not be used.


## v0.9 - 2026-10-09

- Canonical `SPARK-FS-v0.9` Fiat-Shamir transcript.
- Verifier-side header reconstruction and mismatch rejection.
- Final scalar or batch evaluation vector bound into the transcript.
- Legacy `SPARK-SKIP-v0.6` markers removed from v0.9.
- Public gate seed pinned to `5884642712365344205`.
- `n=20, k=2, i0=3` setup counter pinned to `0`.
- 192-bit release query count pinned to `s=407`; `s=406` rejected.
- Added v0.9 smoke benchmark and benchmark provenance.
- Pinned Rust `1.97.1`.
- Added fmt, Clippy, and test CI.
- v0.9 proof size: `590977` bytes.
- Header: `148` bytes.
- Wrapper: `153` bytes.

## v0.8

Frozen public release source:

`b8e80812856965bb8b7501e0459e58fc0fbbdab2`

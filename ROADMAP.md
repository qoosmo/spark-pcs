# SPARK roadmap

## Current status (`main`, v0.10)
- **Protocol:** commit, fold at the verifier's challenges, last layer equals $F(z)$. No sumcheck. Hash-based (BLAKE3), with a transparent fixed public setup.
- **Production parameters:** $k=2$, $n=20$, $i_0=3$, gate field $\mathrm{GF}(2^{128})$, challenge field $\mathrm{GF}(2^{256})$, 192-bit target.
  - proved distance $\Delta^*=0.6157093048$ (checked-setup distance theorem);
  - folding radius $\delta=0.2593$; $s=407$ queries; 16 bits of grinding.
- **Gates:** $(t,t+1)$, encoder $a=u+tv$, $b=a+v$, fold $\lambda=z+t$. Seed `0x50643f649c978b38`, counter 0. Theorem 3.19 unchanged.
- **Merkle layout:** one keyed BLAKE3 leaf per query group of $2^m$ entries; an internal node is one compression. Commitment at $n=20$: $7.49$M $\to1.95$M compressions ($m=3$).
- **Profiles:** `compact` ($m=3$, proof 591,562 B) and `fast` ($m=4$, proof 647,522 B). Same soundness and $s$.
- **Measured** (M1, $n=20$, 40 interleaved runs, vs v0.9.1): prover $1709\to722$ ms ($m=3$, $2.37\times$) and $1622\to664$ ms ($m=4$, $2.44\times$) on one thread; $500\to201$ ms and $456\to159$ ms on eight. Verifier $11.0\to7.1$ ms ($m=3$).
- **Setup convention:** the checked distance certificate fails with probability at most $2^{-128}$, as a one-time event that no prover attempt can re-roll. Conditioned on the accepted setup, online soundness targets 192 bits.
- **Reproduce older layouts:** `--features rc1-layout` (pair leaves, format 10); `--no-default-features --features legacy-gates` (v0.9 gates).

## Open items

### Engineering
1. ~~Freeze v0.10~~ done (v0.10). ~~Group leaves, keyed node hashing~~ done.
2. **Batched SIMD Merkle hashing** (one tree level per call, NEON / AVX2), bit-identical to v0.10 roots.
3. **x86 PCLMUL backend** for $\mathrm{GF}(2^{128})$; keep the portable reference.
4. **Opening-point adapter:** open at an arbitrary point, not only at the protocol's own challenges. This is required to use SPARK as a plug-in PCS.
5. **Zero-knowledge hiding.**
6. **Field-generic code and parameter planner.** Includes tower-basis input/output through a fixed $\mathbb F_2$-linear isomorphism $\varphi$, applied only at the boundary. Evaluation commutes with it: $\varphi(F(z))=(\varphi F)(\varphi z)$.
7. **Field benchmark:** GHASH basis vs binary tower vs GF(2^8)/GFNI, on CPU and then FPGA.

### Theory
1. **Knowledge soundness and round-by-round soundness** write-ups.
2. **Compact $k=3$ profile.** Today: $i_0=2$, $\Delta=0.7571$, $s=277$. With a checked $C_3=[64,8]$ prefix ($\binom{64}{8}\approx4.4\cdot10^9$ minors), $\Delta_3=0.7771$, and the 1.5-Johnson-radius correlated-agreement theorem for linear codes (Gao–Kan–Li, ePrint 2024/1810, Thm 3) gives $s=261$.
3. **Distance beyond $\Delta^*=0.6157$.** A refinement by unions over canonical bad-support chains was worked out in detail: node identities, coverage, conservation, canonical closure. It does not improve $\Delta^*$ once the union over intermediate supports is counted exactly. Open question: a level-by-level argument in the style of the checked-setup theorem that avoids listing supports.
4. **Small-field packing without sumcheck.** Pack 16 polynomials over $\mathrm{GF}(2^8)$ into one polynomial over $\mathrm{GF}(2^{128})$, and recover the evaluations from openings on the Frobenius orbit $\{\sigma^jz\}$ through a Moore matrix. Open: a sumcheck-free multi-point opening on the orbit.
5. **Lean formalization:** first version in progress, section by section (`lean/`).

### Paper
- ~~GKL lemma, specialized gates, $k=3$ record, setup wording, §7.2 leaf layout~~ done.

### Lean (deferred)
- Agent rounds for §5–6 Protocol/completeness and Soundness (Brief L1 tasks 3–4).

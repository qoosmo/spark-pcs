# SPARK roadmap

## Current status (`main`, v0.9.1)
- **Protocol:** commit, fold at the verifier's challenges, last layer equals $F(z)$. No sumcheck. Hash-based (BLAKE3), with a transparent fixed public setup.
- **Production parameters:** $k=2$, $n=20$, $i_0=3$, gate field $\mathrm{GF}(2^{128})$, challenge field $\mathrm{GF}(2^{256})$, 192-bit target.
  - proved distance $\Delta^*=0.6157093048$ (checked-setup distance theorem);
  - folding radius $\delta=0.2593$; $s=407$ queries; 16 bits of grinding.
- **Proof size:** about 591 KB at $n=20$.
- **Setup convention:** the setup comes from the fixed seed `BLAKE3("SPARK-SEED-v0.9")`. The checked distance certificate fails with probability at most $2^{-128}$, as a one-time event that no prover attempt can re-roll. Conditioned on the accepted setup, online soundness targets 192 bits.

## In progress: v0.10, specialized gates $(t,t+1)$ (branch `brief18q-tplus1`)
- **Gates:** $(t^0,t^1)=(t,t+1)$ with one uniform $t$ per parent.
- **Encoder:** $a=u+tv$, $b=a+v$, i.e. one multiplication per pair.
- **Fold:** denominator-free, $\lambda=z+t$.
- **Security unchanged:** the one-level rank-saturation lemma needs only deterministic double-parent constraints, one uniform point per singleton, and independence across parents. So $\Delta^*$ and $s=407$ are unchanged.
- **Verified:**
  - encode multiplications −50%; fold −2 multiplications per gate; identical hash count;
  - fast path bit-for-bit equal to the generic path; evaluation identity on 1000 positions;
  - identical structure before deduplication; cross-version rejection.
- **Measured** (Apple M1, $n=20$, 20 interleaved runs per family): prover −17.4% on 1 thread (1747 → 1443 ms) and −14.5% on 8 threads (524 → 448 ms). Proof +0.27%, from different query positions only.
- **New public setup:** seed `0x50643f649c978b38` (`SPARK-SEED-v0.10-tplus1`), counter 0; checked prefix $C_3=[32,8]$ passes on the first attempt.

## Open items

### Engineering
1. **Freeze v0.10:** default gates, header/transcript version, pinned constants, CHANGELOG, tag `v0.10-rc1`.
2. **Faster Merkle hashing, bit-identical outputs.** Commit is about 67% of the single-thread prover (about 203 ns per hash). Use direct single-block BLAKE3 compression plus batched SIMD (NEON / AVX2).
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
- Add the 1.5-Johnson folding lemma (GKL) with its citation.
- Add the specialized-gates section.
- Add the $k=3$ record and the setup wording.
- Update the benchmark tables to v0.10.

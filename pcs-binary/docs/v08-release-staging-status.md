# v0.8 release staging status

## Task 1
Waiting for Ali's scheduled final long run. No v0.8 tag is created by the staging installer.

## Task 2
Prepared now:
- `src/bin/spark-params.rs`
- README `Parameters and security`
- `scripts/v08-freeze-metadata.sh`
- `scripts/package-v08-public-repo.sh`
- `docs/fiat-shamir-v08.tex`

The exact `bench -- --v08` final table driver is deferred until the final Task 1 grid exists, so it cannot print stale numbers.

## Task 3
- Fiat-Shamir write-up: prepared.
- x86/AVX2 fair baseline: not done on the current Apple-Silicon machine.
- Large-batch policy: documented as batches of 16 by default; no core batch implementation change was made during staging.

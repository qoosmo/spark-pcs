<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# SPARK v0.9 Fiat-Shamir transcript

SPARK v0.9 uses a canonical Fiat-Shamir header that binds:

- `SPARK-FS-v0.9`
- proof format version `9`
- hash and field identifiers
- `alpha = x^121`
- `n, k, i0, s, g, t`
- explicit committed-level schedule
- canonical 32-byte gate seed
- setup counter
- `SPARK-GATE-v0.7`

The public gate seed is:

`5884642712365344205`

For `n=20, k=2, i0=3`, the pinned setup counter is:

`0`

`target_bits` is verifier policy and is not serialized.

The verifier recomputes the query count from `(n,k,i0,g)` and the security target, and rejects any parameter set with fewer queries.

For the 192-bit release parameters:

- `s = 407`
- fold term = `192.008` bits
- query term = `192.263` bits

Serialization sizes:

- header = `148` bytes
- wrapper = `153` bytes

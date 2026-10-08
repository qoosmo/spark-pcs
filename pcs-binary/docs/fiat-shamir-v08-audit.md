# SPARK v0.8 Fiat-Shamir audit

Frozen tag: `v0.8` = `b8e80812856965bb8b7501e0459e58fc0fbbdab2`.

Present in v0.8:
- transcript/domain labels for fold, grinding and queries;
- initial commitment root;
- committed folded roots before later fold challenges;
- full batch final-evaluation vector before grinding/query derivation;
- grinding nonce before query derivation;
- regression test `last_layer_binds_queries`.

Gap:
- the transcript initializer does not explicitly serialize all of
  `n`, `k`, `s`, public gate seed, and checked-setup counter.

This is a v0.9 transcript-hardening item. The v0.8 tag is intentionally unchanged.

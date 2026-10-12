// SPDX-License-Identifier: MIT OR Apache-2.0
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_one_blake3(c: &mut Criterion) {
    let input = [0u8; 64];

    c.bench_function("blake3_one_64B_hash", |b| {
        b.iter(|| {
            black_box(blake3::hash(black_box(&input)));
        })
    });
}

criterion_group!(benches, bench_one_blake3);
criterion_main!(benches);

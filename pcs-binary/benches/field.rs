// SPDX-License-Identifier: MIT OR Apache-2.0
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spark_binary::field::F128;
fn bench(c: &mut Criterion) {
    let a = F128(0x123456789abcdef0fedcba9876543211);
    let b = F128(0xfedcba9876543211123456789abcdef0);
    c.bench_function("gf2_128_mul_portable", |x| {
        x.iter(|| black_box(a) * black_box(b))
    });
}
criterion_group!(benches, bench);
criterion_main!(benches);

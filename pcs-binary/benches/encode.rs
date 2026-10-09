// SPDX-License-Identifier: MIT OR Apache-2.0
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use spark_binary::{
    encode::{encode, GateFamily},
    field::F128,
};
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for &n in &[12usize, 14, 16] {
        let k = 2usize;
        let mut rng = StdRng::seed_from_u64(7 + n as u64);
        let fam = GateFamily::random(n, k, &mut rng);
        let coeffs = (0..(1usize << n))
            .map(|_| F128::random(&mut rng))
            .collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| encode(black_box(&coeffs), black_box(&fam)))
        });
    }
    group.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);

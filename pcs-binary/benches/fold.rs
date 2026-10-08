use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use spark_binary::{field::F128, fold::fold_level_precomputed, gates::Gate};
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_precomputed_lambda");
    for &lg in &[14usize, 16, 18] {
        let pairs = 1usize << lg;
        let mut rng = StdRng::seed_from_u64(99 + lg as u64);
        let word = (0..2 * pairs)
            .map(|_| F128::random(&mut rng))
            .collect::<Vec<_>>();
        let lambdas = (0..pairs)
            .map(|_| F128::random(&mut rng))
            .collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::from_parameter(lg), &lg, |b, _| {
            b.iter(|| fold_level_precomputed(black_box(&word), black_box(&lambdas)))
        });
    }
    group.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);

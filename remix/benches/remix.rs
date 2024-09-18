use criterion::{criterion_group, criterion_main, Criterion};
use elastic_elgamal::{group::Ristretto, Ciphertext, Keypair};
use format as f;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};

const N_BITS: usize = 25600;
const SMALL_N_BITS: usize = 10;

fn setup_bench(
    bit_count: usize,
) -> (
    Keypair<Ristretto>,
    Vec<Ciphertext<Ristretto>>,
    Vec<Ciphertext<Ristretto>>,
    (impl Rng + CryptoRng),
) {
    let mut rng = StdRng::seed_from_u64(7);
    let key_pair = Keypair::generate(&mut rng);
    let pub_key = key_pair.public();

    let mut encrypt =
        |i: usize| -> Ciphertext<Ristretto> { pub_key.encrypt((i % 2) as u64, &mut rng) };
    let ct1: Vec<_> = (0..bit_count).map(&mut encrypt).collect();
    let ct2: Vec<_> = (0..bit_count).map(&mut encrypt).collect();

    (key_pair, ct1, ct2, rng)
}

fn bench_shuffle_pairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shuffle pairs");
    group.sample_size(60);

    let (_key_pair, mut ct1, mut ct2, mut rng) = setup_bench(N_BITS);

    group.bench_function("base", |b| {
        b.iter(|| {
            remix::shuffle_pairs(&mut ct1, &mut ct2, &mut rng);
        })
    });

    group.bench_function(f!("base {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::shuffle_pairs(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                &mut rng,
            );
        })
    });
}

fn bench_shuffle_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shuffle bits");

    let (_key_pair, mut ct1, mut ct2, mut rng) = setup_bench(N_BITS);

    group.bench_function("base", |b| {
        b.iter(|| {
            remix::shuffle_bits(&mut ct1, &mut ct2, &mut rng);
        })
    });

    group.bench_function(f!("base {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::shuffle_bits(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                &mut rng,
            );
        })
    });
}

fn bench_rerandomise(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rerandomise");

    let (key_pair, mut ct1, mut ct2, mut rng) = setup_bench(N_BITS);
    let pub_key = key_pair.public();

    group.sample_size(20);
    group.bench_function("base", |b| {
        b.iter(|| {
            remix::rerandomise(&mut ct1, &mut ct2, pub_key, &mut rng);
        })
    });

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::par::rerandomise(&mut ct1, &mut ct2, pub_key);
        })
    });

    group.bench_function(f!("parallel {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::par::rerandomise(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                pub_key,
            );
        })
    });
}

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("All");

    let (key_pair, mut ct1, mut ct2, ..) = setup_bench(N_BITS);
    let pub_key = key_pair.public();

    group.sample_size(20);
    group.bench_function("base", |b| {
        b.iter(|| {
            remix::remix(&mut ct1, &mut ct2, pub_key);
        })
    });

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::par::remix(&mut ct1, &mut ct2, pub_key);
        })
    });

    group.bench_function(f!("parallel {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::par::remix(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                pub_key,
            );
        })
    });
}

criterion_group!(
    benches,
    bench_shuffle_pairs,
    bench_shuffle_bits,
    bench_rerandomise,
    bench_all,
);
criterion_main!(benches);

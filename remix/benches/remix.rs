use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};

const N_SIZE: usize = 25600;

fn setup_bench() -> (Vec<Ciphertext>, Vec<Ciphertext>, (impl Rng + CryptoRng)) {
    let mut rng = StdRng::seed_from_u64(7);
    let dec_key = DecryptionKey::new(&mut rng);
    let enc_key = dec_key.encryption_key();

    let mut encrypt = |i: usize| -> Ciphertext {
        let m = &Scalar::from((i % 2) as u32) * &GENERATOR_TABLE;
        enc_key.encrypt(m, &mut rng)
    };
    let ct1: Vec<_> = (0..N_SIZE).map(&mut encrypt).collect();
    let ct2: Vec<_> = (0..N_SIZE).map(&mut encrypt).collect();

    (ct1, ct2, rng)
}

fn bench_shuffle_pairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shuffle pairs");
    group.sample_size(60);

    let (mut ct1, mut ct2, mut rng) = setup_bench();

    group.bench_function("base", |b| {
        b.iter(|| {
            remix::shuffle_pairs(&mut ct1, &mut ct2, &mut rng);
        })
    });
}

fn bench_shuffle_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shuffle bits");

    let (mut ct1, mut ct2, mut rng) = setup_bench();

    group.bench_function("base", |b| {
        b.iter(|| {
            remix::shuffle_bits(&mut ct1, &mut ct2, &mut rng);
        })
    });
}

fn bench_rerandomise(c: &mut Criterion) {
    let mut group = c.benchmark_group("Rerandomise");

    let (mut ct1, mut ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    group.sample_size(20);
    group.bench_function("base", |b| {
        b.iter(|| {
            remix::rerandomise(&mut ct1, &mut ct2, &enc_key, &mut rng);
        })
    });

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::par::rerandomise(&mut ct1, &mut ct2, &enc_key);
        })
    });
}

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("All");

    let (mut ct1, mut ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    group.sample_size(20);
    group.bench_function("base", |b| {
        b.iter(|| {
            remix::remix(&mut ct1, &mut ct2, &enc_key);
        })
    });

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::par::remix(&mut ct1, &mut ct2, &enc_key);
        })
    });
}

criterion_group!(
    remix_benches,
    bench_shuffle_pairs,
    bench_shuffle_bits,
    bench_rerandomise,
    bench_all,
);
criterion_main!(remix_benches);

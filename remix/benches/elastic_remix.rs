use criterion::{criterion_group, criterion_main, Criterion};
use elastic_elgamal::{group::Ristretto, Ciphertext, Keypair};
use format as f;
use rand::{rngs::StdRng, SeedableRng};

const N_BITS: usize = 25600;
const SMALL_N_BITS: usize = 10;

fn setup_bench(
    bit_count: usize,
) -> (
    Vec<Ciphertext<Ristretto>>,
    Vec<Ciphertext<Ristretto>>,
    Keypair<Ristretto>,
) {
    let mut rng = StdRng::seed_from_u64(7);
    let receiver = Keypair::<Ristretto>::generate(&mut rng);
    let enc_key = receiver.public();

    let mut encrypt = |m: usize| -> Ciphertext<Ristretto> { enc_key.encrypt(m as u32, &mut rng) };

    let ct1: Vec<_> = (0..bit_count).map(&mut encrypt).collect();
    let ct2: Vec<_> = (0..bit_count).map(&mut encrypt).collect();

    (ct1, ct2, receiver)
}

fn bench_rerandomise(c: &mut Criterion) {
    let mut group = c.benchmark_group("Elastic rerandomise");

    let (mut ct1, mut ct2, receiver) = setup_bench(N_BITS);
    let enc_key = receiver.public();

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::elastic::rerandomise(&mut ct1, &mut ct2, enc_key);
        })
    });

    group.bench_function(f!("parallel {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::elastic::rerandomise(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                enc_key,
            );
        })
    });
}

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("Elastic all");

    let (mut ct1, mut ct2, receiver) = setup_bench(N_BITS);
    let enc_key = receiver.public();

    group.sample_size(100);
    group.bench_function("parallel", |b| {
        b.iter(|| {
            remix::elastic::remix(&mut ct1, &mut ct2, enc_key);
        })
    });

    group.bench_function(f!("parallel {SMALL_N_BITS} bit subset"), |b| {
        b.iter(|| {
            remix::elastic::remix(
                &mut ct1[0..SMALL_N_BITS],
                &mut ct2[0..SMALL_N_BITS],
                enc_key,
            );
        })
    });
}

criterion_group!(benches, bench_rerandomise, bench_all);
criterion_main!(benches);

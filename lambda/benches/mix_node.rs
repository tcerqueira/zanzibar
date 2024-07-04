use criterion::{criterion_group, criterion_main, Criterion};
use lambda::{mix_node::EncryptedCodes, testing};
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use reqwest::Client;
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

const N_BITS: usize = 25600;

fn setup_bench() -> (Vec<Ciphertext>, Vec<Ciphertext>, (impl Rng + CryptoRng)) {
    let mut rng = StdRng::seed_from_u64(7);
    let dec_key = DecryptionKey::new(&mut rng);
    let enc_key = dec_key.encryption_key();

    let mut encrypt = |i: usize| -> Ciphertext {
        let m = &Scalar::from((i % 2) as u32) * &GENERATOR_TABLE;
        enc_key.encrypt(m, &mut rng)
    };
    let ct1: Vec<_> = (0..N_BITS).map(&mut encrypt).collect();
    let ct2: Vec<_> = (0..N_BITS).map(&mut encrypt).collect();

    (ct1, ct2, rng)
}

fn bench_serialization_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialize json");

    let (ct1, ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    let payload = EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key),
    };

    group.bench_function("to string", |b| {
        b.iter(|| {
            let _string = serde_json::to_string(&payload);
        })
    });

    group.bench_function("to value", |b| {
        b.iter(|| {
            let _value = serde_json::to_value(&payload);
        })
    });
}

fn bench_deserialization_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("Deserialize json");

    let (ct1, ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    let payload = EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key),
    };
    let payload = serde_json::to_string(&payload).unwrap();

    group.bench_function("from string", |b| {
        b.iter(|| {
            let _value: EncryptedCodes = serde_json::from_str(&payload).unwrap();
        })
    });
}

fn bench_requests(c: &mut Criterion) {
    let mut group = c.benchmark_group("Request");

    let (ct1, ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let test_app = rt.block_on(async { testing::create_app().await });
    let client = reqwest::Client::new();

    let payload = EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key),
    };

    async fn bench_fn(
        client: &Client,
        port: u16,
        payload: &EncryptedCodes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _response: EncryptedCodes = client
            .post(format!("http://localhost:{port}/remix"))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        Ok(())
    }

    group.bench_function("send and receive", |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(&client, test_app.port, &payload))
    });

    test_app.join_handle.abort();
}

criterion_group!(
    mix_node_benches,
    bench_serialization_json,
    bench_deserialization_json,
    bench_requests,
);
criterion_main!(mix_node_benches);

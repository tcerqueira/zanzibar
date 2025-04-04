use bitvec::{
    order::{BitOrder, Lsb0},
    store::BitStore,
    vec::BitVec,
};
use criterion::{criterion_group, criterion_main, Criterion};
use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Keypair, SecretKey};
use format as f;
use mix_node::{
    config::get_configuration_with, crypto::Ciphertext, test_helpers, EncryptedCodes, N_BITS,
};
use rand::{rngs::StdRng, SeedableRng};
use reqwest::Client;
use std::{ops::Range, sync::Arc};
use tokio_stream::StreamExt;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_SMALL_BITS: usize = 10;
const N_THREADS: u16 = 11;

fn setup_bench() -> (Vec<Ciphertext>, Vec<Ciphertext>, Keypair<Ristretto>) {
    let mut rng = StdRng::seed_from_u64(7);
    let receiver = Keypair::generate(&mut rng);
    let enc_key = receiver.public();

    let mut encrypt = |i: usize| -> Ciphertext { enc_key.encrypt((i % 2) as u32, &mut rng) };
    let ct1: Vec<_> = (0..N_BITS).map(&mut encrypt).collect();
    let ct2: Vec<_> = (0..N_BITS).map(&mut encrypt).collect();

    (ct1, ct2, receiver)
}

fn payload_subset(codes: &EncryptedCodes, range: Range<usize>) -> EncryptedCodes {
    EncryptedCodes {
        x_code: codes.x_code[range.clone()].to_vec(),
        y_code: codes.y_code[range].to_vec(),
        enc_key: codes.enc_key.clone(),
    }
}

fn bench_mix_node(c: &mut Criterion) {
    let mut group = c.benchmark_group("Request");
    group.sample_size(20);

    let curr_dir = std::env::current_dir().unwrap();
    let config = get_configuration_with(curr_dir.join("config")).unwrap();
    let (ct1, ct2, receiver) = setup_bench();
    let enc_key = receiver.public();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let test_app = rt.block_on(test_helpers::create_app(config));
    let client = reqwest::Client::new();

    let payload = Arc::new(EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key.clone()),
    });

    async fn bench_fn(
        client: Client,
        concurrent_req: u16,
        port: u16,
        payload: Arc<EncryptedCodes>,
    ) -> anyhow::Result<()> {
        let mut join_handles = Vec::with_capacity(concurrent_req as usize);
        for _ in 0..concurrent_req {
            let client = client.clone();
            let payload = Arc::clone(&payload);
            let handle = tokio::spawn(async move {
                let _response: EncryptedCodes = client
                    .post(format!("http://localhost:{port}/remix"))
                    .json(&payload)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
            });

            join_handles.push(handle);
        }

        for handle in join_handles {
            let _ = handle.await;
        }

        Ok(())
    }

    group.bench_function("one request", |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(client.clone(), 1, test_app.port, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel"), |b| {
        b.to_async(&rt).iter(|| {
            bench_fn(
                client.clone(),
                N_THREADS,
                test_app.port,
                Arc::clone(&payload),
            )
        })
    });

    let payload = Arc::new(payload_subset(&payload, 0..N_SMALL_BITS));

    group.bench_function(f!("one request {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(client.clone(), 1, test_app.port, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt).iter(|| {
            bench_fn(
                client.clone(),
                N_THREADS,
                test_app.port,
                Arc::clone(&payload),
            )
        })
    });

    async fn bench_final_fn(
        client: Client,
        dec_key: &SecretKey<Ristretto>,
        concurrent_req: u16,
        port: u16,
        payload: Arc<EncryptedCodes>,
    ) -> anyhow::Result<usize> {
        let mut join_handles = Vec::with_capacity(concurrent_req as usize);
        for _ in 0..concurrent_req {
            let client = client.clone();
            let payload = Arc::clone(&payload);
            let dec_key = dec_key.clone();
            let handle = tokio::spawn(async move {
                let EncryptedCodes {
                    x_code,
                    y_code,
                    enc_key: _,
                } = client
                    .post(format!("http://localhost:{port}/remix"))
                    .json(&payload)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                let x_bits: BitVec<usize, Lsb0> =
                    BitVec::from_iter(decrypt_bits(&x_code, &dec_key));
                let y_bits: BitVec<usize, Lsb0> =
                    BitVec::from_iter(decrypt_bits(&y_code, &dec_key));

                hamming_distance(x_bits, y_bits) > 8
            });

            join_handles.push(handle);
        }

        let count = tokio_stream::iter(join_handles)
            .then(|handle| async move { handle.await.unwrap() })
            .filter(|&is_same| is_same)
            .fold(0, |acc, _| acc + 1)
            .await;

        Ok(count)
    }

    group.bench_function("final send+remix+receive+decrypt+hamming", |b| {
        b.to_async(&rt).iter(|| {
            bench_final_fn(
                client.clone(),
                receiver.secret(),
                N_THREADS,
                test_app.port,
                Arc::clone(&payload),
            )
        })
    });

    test_app.join_handle.abort();
}

fn bench_serialization_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialize json");

    let (ct1, ct2, receiver) = setup_bench();
    let enc_key = receiver.public();

    let payload = EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key.clone()),
    };

    group.bench_function("to string", |b| {
        b.iter(|| {
            let _string = serde_json::to_string(&payload);
        })
    });

    let payload = payload_subset(&payload, 0..N_SMALL_BITS);

    group.bench_function(f!("to string {N_SMALL_BITS} bits subset"), |b| {
        b.iter(|| {
            let _string = serde_json::to_string(&payload);
        })
    });
}

fn bench_deserialization_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("Deserialize json");

    let (ct1, ct2, receiver) = setup_bench();
    let enc_key = receiver.public();

    let payload = EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key.clone()),
    };
    let payload_str = serde_json::to_string(&payload).unwrap();

    group.bench_function("from string", |b| {
        b.iter(|| {
            let _value: EncryptedCodes = serde_json::from_str(&payload_str).unwrap();
        })
    });

    let payload = payload_subset(&payload, 0..N_SMALL_BITS);
    let payload_str = serde_json::to_string(&payload).unwrap();

    group.bench_function(f!("from string {N_SMALL_BITS} bits subset"), |b| {
        b.iter(|| {
            let _value: EncryptedCodes = serde_json::from_str(&payload_str).unwrap();
        })
    });
}

fn hamming_distance<T: BitStore, O: BitOrder>(bv1: BitVec<T, O>, bv2: BitVec<T, O>) -> usize {
    (bv1 ^ bv2).count_ones()
}

pub fn decrypt_bits<'a>(
    ct: &'a [Ciphertext],
    pk: &'a SecretKey<Ristretto>,
) -> impl Iterator<Item = bool> + 'a {
    ct.iter().map(|ct| {
        let point = pk.decrypt(*ct, &DiscreteLogTable::new(0..=1)).unwrap();
        point != 0u64
    })
}

criterion_group!(
    benches,
    bench_mix_node,
    bench_serialization_json,
    bench_deserialization_json
);
criterion_main!(benches);

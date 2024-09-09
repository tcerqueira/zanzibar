use criterion::{criterion_group, criterion_main, Criterion};
use format as f;
use mix_node::{
    config::get_configuration,
    grpc::proto::{self, mix_node_client::MixNodeClient},
    test_helpers, EncryptedCodes, N_BITS,
};
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use reqwest::Client;
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};
use std::{ops::Range, sync::Arc};
use tonic::transport::Channel;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_SMALL_BITS: usize = 10;
const N_THREADS: u16 = 11;

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

fn payload_subset(codes: &EncryptedCodes, range: Range<usize>) -> EncryptedCodes {
    EncryptedCodes {
        x_code: codes.x_code[range.clone()].to_vec(),
        y_code: codes.y_code[range].to_vec(),
        enc_key: codes.enc_key,
    }
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

    let payload = payload_subset(&payload, 0..N_SMALL_BITS);

    group.bench_function(f!("to string {N_SMALL_BITS} bits subset"), |b| {
        b.iter(|| {
            let _string = serde_json::to_string(&payload);
        })
    });

    group.bench_function(f!("to value {N_SMALL_BITS} bits subset"), |b| {
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

fn bench_requests(c: &mut Criterion) {
    let mut group = c.benchmark_group("Request");
    group.sample_size(20);

    let config = get_configuration().unwrap();
    let (ct1, ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let test_app = rt.block_on(test_helpers::create_app(config));
    let client = Arc::new(reqwest::Client::new());

    let payload = Arc::new(EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key),
    });

    async fn bench_fn(
        client: Arc<Client>,
        concurrent_req: u16,
        port: u16,
        payload: Arc<EncryptedCodes>,
    ) -> anyhow::Result<()> {
        let mut join_handles = Vec::with_capacity(concurrent_req as usize);
        for _ in 0..concurrent_req {
            let client = Arc::clone(&client);
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
            .iter(|| bench_fn(Arc::clone(&client), 1, test_app.port, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel"), |b| {
        b.to_async(&rt).iter(|| {
            bench_fn(
                Arc::clone(&client),
                N_THREADS,
                test_app.port,
                Arc::clone(&payload),
            )
        })
    });

    let payload = Arc::new(payload_subset(&payload, 0..N_SMALL_BITS));

    group.bench_function(f!("one request {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(Arc::clone(&client), 1, test_app.port, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt).iter(|| {
            bench_fn(
                Arc::clone(&client),
                N_THREADS,
                test_app.port,
                Arc::clone(&payload),
            )
        })
    });

    test_app.join_handle.abort();
}

fn bench_grpc_requests(c: &mut Criterion) {
    let mut group = c.benchmark_group("gRPC request");
    group.sample_size(20);

    let config = get_configuration().unwrap();
    let (ct1, ct2, mut rng) = setup_bench();
    let enc_key = EncryptionKey::from(&Scalar::random(&mut rng) * &GENERATOR_TABLE);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let test_app = rt.block_on(test_helpers::create_grpc(config));
    let client = rt
        .block_on(MixNodeClient::connect(format!(
            "http://localhost:{}",
            test_app.port
        )))
        .unwrap();
    let client = Arc::new(client);

    let payload = Arc::new(EncryptedCodes {
        x_code: ct1,
        y_code: ct2,
        enc_key: Some(enc_key),
    });

    async fn bench_fn(
        client: Arc<MixNodeClient<Channel>>,
        concurrent_req: u16,
        payload: Arc<EncryptedCodes>,
    ) -> anyhow::Result<()> {
        let mut join_handles = Vec::with_capacity(concurrent_req as usize);
        for _ in 0..concurrent_req {
            let mut client = (*client).clone();
            let payload = Arc::clone(&payload);
            let handle = tokio::spawn(async move {
                let proto_codes: proto::EncryptedCodes = (&*payload).into();
                let _response: EncryptedCodes = client
                    .remix(proto_codes)
                    .await
                    .unwrap()
                    .into_inner()
                    .try_into()
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
            .iter(|| bench_fn(Arc::clone(&client), 1, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel"), |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(Arc::clone(&client), N_THREADS, Arc::clone(&payload)))
    });

    let payload = Arc::new(payload_subset(&payload, 0..N_SMALL_BITS));

    group.bench_function(f!("one request {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(Arc::clone(&client), 1, Arc::clone(&payload)))
    });

    group.bench_function(f!("{N_THREADS} parallel {N_SMALL_BITS} bits subset"), |b| {
        b.to_async(&rt)
            .iter(|| bench_fn(Arc::clone(&client), N_THREADS, Arc::clone(&payload)))
    });

    test_app.join_handle.abort();
}

criterion_group!(
    benches,
    bench_serialization_json,
    bench_deserialization_json,
    bench_requests,
    bench_grpc_requests,
);
criterion_main!(benches);

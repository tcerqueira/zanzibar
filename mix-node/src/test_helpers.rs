use crate::{
    config::{get_configuration, ActiveParticipantConfig, Config, CryptoConfig},
    db, grpc, AppState,
};
use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
};
use rand::{CryptoRng, Rng};
use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
use sqlx::PgPool;
use std::{iter, sync::OnceLock};
use tokio::task::JoinHandle;

pub struct TestApp {
    pub port: u16,
    pub join_handle: JoinHandle<()>,
}

pub async fn create_app(config: Config) -> TestApp {
    // Only for debugging purposes
    // init_tracing();

    let Config {
        application: app_config,
        database: db_config,
        crypto: crypto_config,
        ..
    } = config;

    let addr = format!("{}:{}", app_config.host, app_config.port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let conn = db::connect_database(db_config).await;
        // DB unused at the moment
        // sqlx::migrate!()
        //     .run(&conn)
        //     .await
        //     .expect("database migration failed");

        let state = AppState::new(app_config.auth_token, conn, crypto_config);
        axum::serve(listener, crate::rest::app(state))
            .await
            .unwrap();
    });

    TestApp { port, join_handle }
}

pub async fn create_grpc(config: Config) -> TestApp {
    // Only for debugging purposes
    // init_tracing();

    let Config {
        application: app_config,
        database: db_config,
        crypto: crypto_config,
        ..
    } = config;

    let addr = format!("{}:{}", app_config.host, app_config.port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let conn = db::connect_database(db_config).await;
        // DB unused at the moment
        // sqlx::migrate!()
        //     .run(&conn)
        //     .await
        //     .expect("database migration failed");

        let state = AppState::new(app_config.auth_token, conn, crypto_config);
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        grpc::app(state).serve_with_incoming(stream).await.unwrap();
    });

    TestApp { port, join_handle }
}

pub async fn create_network(shares: usize, threshold: usize) -> Vec<TestApp> {
    let mut rng = rand::thread_rng();
    let params = Params::new(shares, threshold);
    const STARTING_PORT: u16 = 8081;

    // Initialize the dealer.
    let dealer = Dealer::<Ristretto>::new(params, &mut rng);
    let (public_poly, poly_proof) = dealer.public_info();
    let key_set =
        PublicKeySet::new(params, public_poly, poly_proof).expect("invalid public key set");

    // Initialize participants based on secret shares provided by the dealer.
    let participants = (0..shares)
        .map(|i| ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i)))
        .collect::<Result<Vec<_>, _>>()
        .expect("active participant invalid");

    let participant_configs: Vec<_> = participants
        .iter()
        .map(|p| ActiveParticipantConfig {
            host: "0.0.0.0".to_string(),
            port: STARTING_PORT + p.index() as u16,
            index: p.index(),
        })
        .collect();

    let crypto_configs: Vec<_> = participants
        .into_iter()
        .map(|p| CryptoConfig {
            whoami: p.index(),
            key_set: p.key_set().clone(),
            secret_key: p.secret_share().clone(),
            participants: participant_configs
                .iter()
                .filter(|c| c.index != p.index()) // exclude itself
                .cloned()
                .collect(),
        })
        .collect();

    let configs: Vec<_> = iter::zip(crypto_configs, participant_configs)
        .map(|(crypto_conf, p)| {
            let mut config = get_configuration().expect("could not get valid configuration");
            config.crypto = crypto_conf;
            config.application.host = p.host;
            config.application.port = p.port;
            config
        })
        .collect();

    let mut test_apps = vec![];
    for config in configs {
        test_apps.push(create_app(config).await);
    }
    test_apps
}

pub async fn populate_database<'p, 'r>(
    pool: &'p PgPool,
    rng: &'r mut (impl Rng + CryptoRng),
    row_count: usize,
    code_len: usize,
) -> Result<(), sqlx::Error> {
    let dec_key = DecryptionKey::new(rng);
    let enc_key = dec_key.encryption_key();

    let rt = &tokio::runtime::Handle::current();
    std::thread::scope(|scope| -> Result<_, sqlx::Error> {
        let mut handles = Vec::with_capacity(row_count);
        for _i in 0..row_count {
            let code: Vec<_> = (0..code_len)
                .map(|_| {
                    let m = rng.gen_bool(0.5) as u32;
                    let m = &Scalar::from(m) * &GENERATOR_TABLE;
                    let r = Scalar::from(123456789u32);
                    enc_key.encrypt_with(m, r)
                })
                .collect();
            let h = scope.spawn(move || rt.block_on(db::insert_code(pool, &code)));
            handles.push(h);
        }
        for handle in handles {
            handle.join().unwrap()?;
        }
        Ok(())
    })?;
    Ok(())
}

#[expect(dead_code)]
fn init_tracing() {
    static TRACING: OnceLock<()> = OnceLock::new();
    TRACING.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    });
}

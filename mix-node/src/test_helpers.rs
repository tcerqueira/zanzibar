use crate::{
    config::{get_configuration, ActiveParticipantConfig, Config, CryptoConfig},
    db, AppState,
};
use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
};
use std::{iter, sync::OnceLock};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

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

    tokio_stream::iter(configs).then(create_app).collect().await
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

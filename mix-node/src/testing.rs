use crate::{config::Config, db, grpc, AppState};
use rand::{CryptoRng, Rng};
use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use std::sync::OnceLock;
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
        ..
    } = config;
    let auth_token = match app_config
        .auth_token
        .as_ref()
        .map(|s| s.expose_secret().as_str())
    {
        None | Some("") => None,
        Some(tok) => Some(tok.to_owned()),
    };

    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let conn = db::connect_database(db_config)
            .await
            .expect("connection to database failed");
        sqlx::migrate!()
            .run(&conn)
            .await
            .expect("database migration failed");

        let state = AppState::new(auth_token, conn);
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
        ..
    } = config;
    let auth_token = match app_config
        .auth_token
        .as_ref()
        .map(|s| s.expose_secret().as_str())
    {
        None | Some("") => None,
        Some(tok) => Some(tok.to_owned()),
    };

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let join_handle = tokio::spawn(async move {
        let conn = db::connect_database(db_config)
            .await
            .expect("connection to database failed");
        sqlx::migrate!()
            .run(&conn)
            .await
            .expect("database migration failed");

        let state = AppState::new(auth_token, conn);
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        grpc::app(state).serve_with_incoming(stream).await.unwrap();
    });

    TestApp { port, join_handle }
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

#[allow(dead_code)]
fn init_tracing() {
    static TRACING: OnceLock<()> = OnceLock::new();
    TRACING.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    });
}

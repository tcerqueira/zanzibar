use crate::config::DatabaseConfig;
use rust_elgamal::Ciphertext;
use secrecy::ExposeSecret;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult, PgSslMode},
    Error, PgPool,
};
use std::time::Duration;

pub async fn connect_database(config: DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    let pool_options = PgPoolOptions::default().acquire_timeout(Duration::from_secs(5));
    let conn_options = PgConnectOptions::new()
        .host(&config.host)
        .username(&config.username)
        .password(config.password.expose_secret())
        .port(config.port)
        .database(&config.database_name)
        .ssl_mode(match &config.require_ssl {
            true => PgSslMode::Require,
            false => PgSslMode::Prefer,
        });

    pool_options.connect_with(conn_options).await
}

pub async fn insert_code(pool: &PgPool, code: &[Ciphertext]) -> Result<PgQueryResult, Error> {
    let code = bincode::serialize(code).expect("failed to serialize code");
    sqlx::query("INSERT INTO iris (code) VALUES ($1);")
        .bind(&code)
        .execute(pool)
        .await
}

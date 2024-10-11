use crate::{config::DatabaseConfig, crypto::Ciphertext};
use anyhow::Context;
use secrecy::ExposeSecret;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult, PgSslMode},
    Error, PgPool, Row,
};
use std::{pin::Pin, time::Duration};
use tokio_stream::StreamExt;

pub async fn connect_database(config: DatabaseConfig) -> PgPool {
    let pool_options = PgPoolOptions::default().acquire_timeout(Duration::from_secs(5));
    let conn_options = PgConnectOptions::new()
        .host(&config.host)
        .username(&config.username)
        .password(config.password.expose_secret())
        .port(config.port)
        .database(&config.database_name)
        .ssl_mode(match config.require_ssl {
            true => PgSslMode::Require,
            false => PgSslMode::Prefer,
        });

    pool_options.connect_lazy_with(conn_options)
}

pub async fn insert_code(pool: &PgPool, code: &[Ciphertext]) -> Result<PgQueryResult, Error> {
    let code = bincode::serialize(code).expect("failed to serialize code");
    sqlx::query("INSERT INTO iris (code) VALUES ($1);")
        .bind(code)
        .execute(pool)
        .await
}

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = T>>>;

pub async fn get_all_codes(pool: &PgPool) -> BoxStream<anyhow::Result<Vec<Ciphertext>>> {
    let stream = sqlx::query("SELECT * FROM iris;").fetch(pool).map(|row| {
        let code: Vec<_> = row
            .context("could not get row")?
            .try_get("code")
            .context("could not get column 'code'")?;
        Ok(bincode::deserialize::<Vec<Ciphertext>>(&code)?)
    });

    Box::pin(stream)
}

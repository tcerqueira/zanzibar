use rust_elgamal::Ciphertext;
use sqlx::{
    postgres::{PgPoolOptions, PgQueryResult},
    Error, PgPool,
};
use std::time::Duration;

pub async fn get_database() -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::default()
        .acquire_timeout(Duration::from_secs(5))
        .connect("postgres://username:password@localhost/iris-codes")
        .await
}

pub async fn insert_code(pool: &PgPool, code: &[Ciphertext]) -> Result<PgQueryResult, Error> {
    let code = bincode::serialize(code).expect("failed to serialize code");
    sqlx::query("INSERT INTO iris (code) VALUES ($1);")
        .bind(&code)
        .execute(pool)
        .await
}

pub mod config;
pub mod db;
pub mod grpc;
pub mod rest;
pub(crate) mod rokio;
pub mod testing;

use elastic_elgamal::{group::Ristretto, Ciphertext as ElasticCiphertext, Keypair, PublicKey};
use rand::{rngs::StdRng, SeedableRng};
use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
use secrecy::Secret;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;
use std::{fmt::Debug, sync::OnceLock};

pub const N_BITS: usize = 25600;

pub struct AppState {
    auth_token: Option<Secret<String>>,
    _pool: PgPool,
    // participants: Vec<ActiveParticipant<Ristretto>>,
}

impl AppState {
    pub fn new(auth_token: Option<String>, pool: PgPool) -> Self {
        Self {
            auth_token: auth_token.map(Secret::new),
            _pool: pool,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCodes {
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<Ciphertext>,
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<Ciphertext>,
    pub enc_key: Option<EncryptionKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticEncryptedCodes {
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<ElasticCiphertext<Ristretto>>,
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<ElasticCiphertext<Ristretto>>,
    pub enc_key: Option<PublicKey<Ristretto>>,
}

#[allow(unused)]
fn deserialize_vec_with_capacity<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut vec = Vec::with_capacity(N_BITS);
    Vec::deserialize_in_place(deserializer, &mut vec)?;
    Ok(vec)
}

fn enc_key() -> &'static EncryptionKey {
    // TODO: remove hardcoded encryption key from a fixed seed
    static ENC_KEY: OnceLock<EncryptionKey> = OnceLock::new();
    ENC_KEY.get_or_init(|| {
        EncryptionKey::from(RistrettoPoint::random(&mut StdRng::seed_from_u64(
            1234567890,
        )))
    })
}

fn elastic_enc_key() -> &'static PublicKey<Ristretto> {
    // TODO: remove hardcoded encryption key from a fixed seed
    static ENC_KEY: OnceLock<PublicKey<Ristretto>> = OnceLock::new();
    ENC_KEY.get_or_init(|| {
        let receiver = Keypair::generate(&mut StdRng::seed_from_u64(1234567890));
        receiver.public().clone()
    })
}

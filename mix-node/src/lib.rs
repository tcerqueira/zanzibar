pub mod grpc;
pub mod rest;
pub(crate) mod rokio;
pub mod testing;

use rand::{rngs::StdRng, SeedableRng};
use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::OnceLock;

pub const N_BITS: usize = 25600;

#[derive(Debug, Clone)]
pub struct AppState {
    auth_token: Option<&'static str>,
}

impl AppState {
    pub fn new(auth_token: Option<String>) -> Self {
        Self {
            auth_token: auth_token.map(|s| &*s.leak()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCodes {
    #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<Ciphertext>,
    #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<Ciphertext>,
    pub enc_key: Option<EncryptionKey>,
}

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

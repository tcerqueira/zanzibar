pub mod config;
pub mod crypto;
pub mod db;
pub mod rest;
pub mod rokio;
pub mod test_helpers;

use config::CryptoConfig;
use crypto::Ciphertext;
use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, PublicKeySet},
    PublicKey,
};
use reqwest::Client;
use secrecy::Secret;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;
use std::fmt::Debug;

pub const N_BITS: usize = 25600;

pub struct AppState {
    http_client: Client,
    auth_token: Option<Secret<String>>,
    #[expect(dead_code)]
    pool: PgPool,
    crypto: CryptoState,
}

impl AppState {
    pub fn new(
        auth_token: Option<Secret<String>>,
        pool: PgPool,
        crypto_config: CryptoConfig,
    ) -> Self {
        Self {
            http_client: Client::new(),
            auth_token,
            pool,
            crypto: crypto_config
                .try_into()
                .expect("failed to create active participant from config"),
        }
    }

    fn pub_key_set(&self) -> &PublicKeySet<Ristretto> {
        self.crypto.active_participant.key_set()
    }
}

struct CryptoState {
    active_participant: ActiveParticipant<Ristretto>,
    participants: Vec<ParticipantId>,
}

#[expect(dead_code)]
#[derive(Debug, Clone)]
struct ParticipantId {
    index: usize,
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCodes {
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<Ciphertext>,
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<Ciphertext>,
    pub enc_key: Option<PublicKey<Ristretto>>,
}

#[expect(dead_code)]
fn deserialize_vec_with_capacity<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut vec = Vec::with_capacity(N_BITS);
    Vec::deserialize_in_place(deserializer, &mut vec)?;
    Ok(vec)
}

impl TryFrom<CryptoConfig> for CryptoState {
    type Error = elastic_elgamal::sharing::Error;

    fn try_from(config: CryptoConfig) -> Result<Self, Self::Error> {
        let participants = config
            .participants
            .into_iter()
            .filter(|p| p.index != config.whoami)
            .map(|p| ParticipantId {
                index: p.index,
                url: p.url,
            })
            .collect::<Vec<_>>();

        Ok(Self {
            active_participant: ActiveParticipant::new(
                config.key_set,
                config.whoami,
                config.secret_key,
            )?,
            participants,
        })
    }
}

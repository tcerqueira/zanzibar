pub mod config;
pub mod crypto;
pub mod db;
pub mod rest;
pub(crate) mod rokio;
pub mod test_helpers;

use config::CryptoConfig;
use elastic_elgamal::{
    group::Ristretto, sharing::ActiveParticipant, Ciphertext, Keypair, PublicKey,
};
use rand::{rngs::StdRng, SeedableRng};
use secrecy::Secret;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;
use std::{fmt::Debug, sync::OnceLock};

pub const N_BITS: usize = 25600;

pub struct AppState {
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
            auth_token,
            pool,
            crypto: crypto_config
                .try_into()
                .expect("failed to create active participant from config"),
        }
    }
}

struct CryptoState {
    active_particiapnt: ActiveParticipant<Ristretto>,
    participants: Vec<ParticipantState>,
}

#[expect(dead_code)]
struct ParticipantState {
    index: usize,
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCodes {
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<Ciphertext<Ristretto>>,
    // #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<Ciphertext<Ristretto>>,
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

fn enc_key() -> &'static PublicKey<Ristretto> {
    // TODO: remove hardcoded encryption key from a fixed seed
    static ENC_KEY: OnceLock<PublicKey<Ristretto>> = OnceLock::new();
    ENC_KEY.get_or_init(|| {
        let receiver = Keypair::generate(&mut StdRng::seed_from_u64(1234567890));
        receiver.into_tuple().0
    })
}

impl TryFrom<CryptoConfig> for CryptoState {
    type Error = elastic_elgamal::sharing::Error;

    fn try_from(config: CryptoConfig) -> Result<Self, Self::Error> {
        let participants = config
            .participants
            .into_iter()
            .filter(|p| p.index != config.whoami)
            .map(|p| ParticipantState {
                index: p.index,
                url: p.url,
            })
            .collect::<Vec<_>>();

        Ok(Self {
            active_particiapnt: ActiveParticipant::new(
                config.key_set,
                config.whoami,
                config.secret_key,
            )?,
            participants,
        })
    }
}

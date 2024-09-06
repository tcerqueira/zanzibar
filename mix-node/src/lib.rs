pub mod config;
pub mod db;
pub mod grpc;
pub mod rest;
pub(crate) mod rokio;
pub mod testing;

use config::CryptoConfig;
use elastic_elgamal::{
    group::Ristretto, sharing::ActiveParticipant, Ciphertext as ElasticCiphertext, Keypair,
    PublicKey,
};
use rand::{rngs::StdRng, SeedableRng};
use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
use secrecy::Secret;
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;
use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::OnceLock,
};

pub const N_BITS: usize = 25600;

pub struct AppState {
    auth_token: Option<Secret<String>>,
    #[expect(dead_code)]
    pool: PgPool,
    #[expect(dead_code)]
    crypto: CryptoState,
}

impl AppState {
    pub fn new(auth_token: Option<String>, pool: PgPool, crypto_config: CryptoConfig) -> Self {
        Self {
            auth_token: auth_token.map(Secret::new),
            pool,
            crypto: crypto_config
                .try_into()
                .expect("failed to create active participant from config"),
        }
    }
}

#[expect(dead_code)]
pub struct CryptoState {
    active_particiapnt: ActiveParticipant<Ristretto>,
    participants: Vec<ParticipantState>,
}

#[expect(dead_code)]
struct ParticipantState {
    index: usize,
    addr: SocketAddr,
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
        receiver.into_tuple().0
    })
}

impl TryFrom<CryptoConfig> for CryptoState {
    type Error = elastic_elgamal::sharing::Error;

    fn try_from(config: CryptoConfig) -> Result<Self, Self::Error> {
        let participants = config
            .participants
            .iter()
            .filter(|p| p.index != config.whoami)
            .map(|p| ParticipantState {
                index: p.index,
                addr: SocketAddr::new(
                    IpAddr::from_str(&p.host).unwrap_or_else(|e| {
                        panic!(
                            "{e}: participant {} with host `{}` is not valid",
                            p.index, p.host
                        )
                    }),
                    p.port,
                ),
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

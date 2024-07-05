pub(crate) mod rokio;
pub mod testing;

pub const N_BITS: usize = 25600;

pub mod mix_node {
    use super::*;

    use axum::extract::DefaultBodyLimit;
    use axum::{response::Json, routing::post, Router};

    use rand::{rngs::StdRng, SeedableRng};
    use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
    use serde::{Deserialize, Deserializer, Serialize};
    use std::sync::OnceLock;

    pub fn app() -> Router {
        Router::new()
            .route("/remix", post(remix_handler))
            // TODO: for security reasons set max instead of disabling (measured payload was ~11MB)
            .layer(DefaultBodyLimit::disable())
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EncryptedCodes {
        #[serde(deserialize_with = "deserialize_vec_with_capacity")]
        pub x_code: Vec<Ciphertext>,
        #[serde(deserialize_with = "deserialize_vec_with_capacity")]
        pub y_code: Vec<Ciphertext>,
        pub enc_key: Option<EncryptionKey>,
    }

    async fn remix_handler(Json(mut codes): Json<EncryptedCodes>) -> Json<EncryptedCodes> {
        // TODO: error handling for vecs of different sizes
        let codes = rokio::spawn(move || {
            let mut rng = rand::thread_rng();
            remix::shuffle_pairs(&mut codes.x_code, &mut codes.y_code, &mut rng);
            remix::shuffle_pairs(&mut codes.x_code, &mut codes.y_code, &mut rng);
            remix::par::rerandomise(
                &mut codes.x_code,
                &mut codes.y_code,
                &codes.enc_key.unwrap_or(*enc_key()),
            );

            codes
        })
        .await;

        Json(codes)
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

    fn deserialize_vec_with_capacity<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        let mut vec = Vec::with_capacity(25600);
        Vec::deserialize_in_place(deserializer, &mut vec)?;
        Ok(vec)
    }
}

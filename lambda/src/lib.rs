pub(crate) mod rokio;
pub mod testing;

pub mod mix_node {
    use super::*;

    use axum::extract::DefaultBodyLimit;
    use axum::{response::Json, routing::post, Router};

    use rand::{rngs::StdRng, SeedableRng};
    use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
    use serde::{Deserialize, Serialize};
    use std::sync::OnceLock;

    fn enc_key() -> &'static EncryptionKey {
        // TODO: remove hardcoded encryption key from a fixed seed
        static ENC_KEY: OnceLock<EncryptionKey> = OnceLock::new();
        ENC_KEY.get_or_init(|| {
            EncryptionKey::from(RistrettoPoint::random(&mut StdRng::seed_from_u64(
                1234567890,
            )))
        })
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EncryptedCodes {
        pub x_code: Vec<Ciphertext>,
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

    pub fn app() -> Router {
        Router::new()
            .route("/remix", post(remix_handler))
            // TODO: for security reasons set max instead of disabling (measured payload was ~11MB)
            .layer(DefaultBodyLimit::disable())
    }
}

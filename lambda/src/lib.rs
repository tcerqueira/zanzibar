pub(crate) mod rokio;
pub mod testing;

pub const N_BITS: usize = 25600;

pub mod mix_node {
    use super::*;

    use axum::extract::{DefaultBodyLimit, Request, State};
    use axum::middleware::{self, Next};
    use axum::response::{IntoResponse, Response};
    use axum::{response::Json, routing::post, Router};

    use axum::http::StatusCode;
    use axum_extra::headers::authorization::Bearer;
    use axum_extra::headers::Authorization;
    use axum_extra::TypedHeader;
    use rand::{rngs::StdRng, SeedableRng};
    use rust_elgamal::{Ciphertext, EncryptionKey, RistrettoPoint};
    use serde::{Deserialize, Deserializer, Serialize};
    use std::sync::OnceLock;

    #[derive(Debug, Clone)]
    pub struct AppState {
        auth_token: Option<String>,
    }

    impl AppState {
        pub fn new(auth_token: Option<String>) -> Self {
            Self { auth_token }
        }
    }

    pub fn app(state: AppState) -> Router {
        Router::new()
            .route("/remix", post(remix_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ))
            .layer(DefaultBodyLimit::max(12_000_000 /* 12MB */))
            .with_state(state)
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EncryptedCodes {
        #[serde(deserialize_with = "deserialize_vec_with_capacity")]
        pub x_code: Vec<Ciphertext>,
        #[serde(deserialize_with = "deserialize_vec_with_capacity")]
        pub y_code: Vec<Ciphertext>,
        pub enc_key: Option<EncryptionKey>,
    }

    async fn remix_handler(
        Json(mut codes): Json<EncryptedCodes>,
    ) -> Result<Json<EncryptedCodes>, StatusCode> {
        if codes.x_code.len() != codes.y_code.len() {
            return Err(StatusCode::BAD_REQUEST);
        }

        let codes = rokio::spawn(move || {
            remix::par::remix(
                &mut codes.x_code,
                &mut codes.y_code,
                &codes.enc_key.unwrap_or(*enc_key()),
            );
            codes
        })
        .await;

        Ok(Json(codes))
    }

    async fn auth_middleware(
        State(AppState { auth_token }): State<AppState>,
        auth_header: Option<TypedHeader<Authorization<Bearer>>>,
        request: Request,
        next: Next,
    ) -> Response {
        let next_run = async { next.run(request).await };

        match (auth_token, auth_header) {
            // AUTH_TOKEN is set on the server and in the request header so we check
            (Some(auth_token), Some(TypedHeader(header_auth_token)))
                if auth_token == header_auth_token.token() =>
            {
                next_run.await
            }
            // AUTH_TOKEN is not set on the server so we disable auth
            (None, _) => next_run.await,
            _ => StatusCode::UNAUTHORIZED.into_response(),
        }
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

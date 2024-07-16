mod auth;
pub(crate) mod rokio;
pub mod routes;
pub mod testing;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::{routing::post, Router};
use rand::{rngs::StdRng, SeedableRng};
use rust_elgamal::{EncryptionKey, RistrettoPoint};
use std::sync::OnceLock;
use tower_http::trace::TraceLayer;

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

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/remix", post(routes::remix_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(12_000_000 /* 12MB */))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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

pub mod error;
mod middleware;
pub mod routes;

use std::sync::Arc;

use crate::AppState;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;

pub fn app(state: AppState) -> Router {
    let state = Arc::new(state);
    let elastic_routes = Router::new()
        .route("/health", get(|| async { "Ok" }))
        .route("/remix", post(routes::elastic_remix_handler))
        .route("/public-key-set", get(routes::elastic_public_key))
        .route("/encrypt", post(routes::elastic_encrypt))
        .route("/decrypt-share", post(routes::elastic_decrypt_share));

    Router::new()
        .nest("/elastic", elastic_routes)
        .route("/remix", post(routes::remix_handler))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware::auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(12_000_000 /* 12MB */))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

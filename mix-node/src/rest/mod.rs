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
    let routes = Router::new()
        .route("/health", get(|| async { "Ok" }))
        .route("/remix", post(routes::remix_handler))
        .route("/public-key-set", get(routes::public_key_set))
        .route("/encrypt", post(routes::encrypt))
        .route("/decrypt-share", post(routes::decrypt_share));

    Router::new()
        .nest("/", routes)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware::auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(12_000_000 /* 12MB */))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

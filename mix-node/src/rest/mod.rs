mod middleware;
mod routes;

use crate::AppState;
use axum::{extract::DefaultBodyLimit, routing::post, Router};
use tower_http::trace::TraceLayer;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/remix", post(routes::remix_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ))
        .layer(DefaultBodyLimit::max(12_000_000 /* 12MB */))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

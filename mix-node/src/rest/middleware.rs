use std::sync::Arc;

use crate::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use secrecy::ExposeSecret;

#[tracing::instrument(skip_all)]
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    request: Request,
    next: Next,
) -> Response {
    let fut_next_run = next.run(request);
    let auth_token = state.auth_token.expose_secret();

    match (auth_token, auth_header) {
        // AUTH_TOKEN is set on the server and in the request header so we check
        (Some(auth_token), Some(TypedHeader(header_auth_token)))
            if *auth_token == *header_auth_token.token() =>
        {
            fut_next_run.await
        }
        // AUTH_TOKEN is not set on the server so we disable auth
        (None, _) => fut_next_run.await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

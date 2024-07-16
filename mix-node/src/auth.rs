use crate::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;

#[tracing::instrument(skip_all)]
pub async fn auth_middleware(
    State(AppState { auth_token }): State<AppState>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    request: Request,
    next: Next,
) -> Response {
    let next_run = async { next.run(request).await };

    match (auth_token, auth_header) {
        // AUTH_TOKEN is set on the server and in the request header so we check
        (Some(auth_token), Some(TypedHeader(header_auth_token)))
            if *auth_token == *header_auth_token.token() =>
        {
            next_run.await
        }
        // AUTH_TOKEN is not set on the server so we disable auth
        (None, _) => next_run.await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

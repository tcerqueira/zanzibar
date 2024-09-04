use crate::AppState;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tonic::{metadata::MetadataValue, Request, Status};

pub fn auth_middleware(
    state: Arc<AppState>,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |req| {
        let auth_token: Option<MetadataValue<_>> = state
            .auth_token
            .as_ref()
            .and_then(|token| format!("Bearer {}", token.expose_secret()).parse().ok());
        let auth_req = req.metadata().get("authorization");

        match (auth_token, auth_req) {
            // AUTH_TOKEN is set on the server and in the request header so we check
            (Some(auth_token), Some(auth_req)) if auth_token == *auth_req => Ok(req),
            // AUTH_TOKEN is not set on the server so we disable auth
            (None, _) => Ok(req),
            _ => Err(Status::unauthenticated("Invalid auth token")),
        }
    }
}

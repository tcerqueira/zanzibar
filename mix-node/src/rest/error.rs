use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("InvalidLength: {0}")]
    InvalidLength(String),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Error::InvalidLength(_) => StatusCode::BAD_REQUEST,
            Error::Unexpected(_) => {
                tracing::error!("{self:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status_code, self.to_string()).into_response()
    }
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidLength(s) => Self::InvalidLength(s),
        }
    }
}

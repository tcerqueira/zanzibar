//! Error types for the application.
//!
//! This module defines the error types used throughout the application,
//! particularly for handling HTTP responses and crypto-related errors.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::crypto::CryptoError;

/// Application-wide error types.
#[derive(Debug, Error)]
pub enum Error {
    /// Error indicating an invalid length was provided
    #[error("InvalidLength: {0}")]
    InvalidLength(String),

    /// Unexpected errors that don't fit other categories
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// Implementation of `IntoResponse` for the application's error types.
///
/// Converts application errors into HTTP responses with appropriate status codes:
/// - `InvalidLength` errors return `400 Bad Request`
/// - `Unexpected` errors return `500 Internal Server Error`
///
/// The response body contains the error message as a string.
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Error::InvalidLength(_) => StatusCode::BAD_REQUEST,
            Error::Unexpected(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

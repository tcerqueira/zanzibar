use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Found invalid ciphertext.")]
    InvalidCiphertext,
    #[error("Found invalid encryption key.")]
    InvalidEncryptionKey,
    #[error("Codes have mismatched lengths. x:{x_len} =/= y:{y_len}")]
    LengthMismatch { x_len: usize, y_len: usize },
}

impl From<MessageError> for Status {
    fn from(error: MessageError) -> Self {
        match error {
            MessageError::InvalidCiphertext
            | MessageError::InvalidEncryptionKey
            | MessageError::LengthMismatch { x_len: _, y_len: _ } => {
                Status::invalid_argument(error.to_string())
            }
        }
    }
}

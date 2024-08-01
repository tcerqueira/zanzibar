use super::{
    proto::{self, mix_node_server::MixNode},
    MessageError,
};
use crate::{rokio, AppState, EncryptedCodes};
use std::sync::Arc;
use tonic::{Request, Response};

#[derive(Debug, Clone)]
pub struct MixNodeService {
    #[allow(unused)] // Example of how to share state in a gRPC app
    state: Arc<AppState>,
}

impl MixNodeService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl MixNode for MixNodeService {
    async fn remix(
        &self,
        request: Request<proto::EncryptedCodes>,
    ) -> tonic::Result<Response<proto::EncryptedCodes>> {
        let mut codes: EncryptedCodes = request.into_inner().try_into()?;

        if codes.x_code.len() != codes.y_code.len() {
            tracing::error!("length mismatch between codes");
            Err(MessageError::LengthMismatch {
                x_len: codes.x_code.len(),
                y_len: codes.y_code.len(),
            })?;
        }

        let codes = rokio::spawn(move || {
            remix::par::remix(
                &mut codes.x_code,
                &mut codes.y_code,
                &codes.enc_key.unwrap_or(*crate::enc_key()),
            );
            codes
        })
        .await;

        Ok(Response::new(codes.into()))
    }
}

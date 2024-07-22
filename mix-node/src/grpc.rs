use crate::rokio;
use crate::routes::EncryptedCodes;
use proto::mix_node_server::{MixNode, MixNodeServer};
use rust_elgamal::{Ciphertext, CompressedRistretto, EncryptionKey};
use thiserror::Error;
use tonic::transport::Server;
use tonic::Status;
use tonic::{transport::server::Router, Request, Response};

pub mod proto {
    tonic::include_proto!("mix_node");
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Found invalid ciphertext.")]
    InvalidCiphertext,
    #[error("Found invalid encryption key.")]
    InvalidEncryptionKey,
    #[error("Codes have mismatched lengths. x:{x_len} =/= y:{y_len}")]
    LengthMismatch { x_len: usize, y_len: usize },
}

#[derive(Debug, Default)]
struct MixNodeService;

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

pub fn service() -> Router {
    // TODO: add bench
    // TODO: add tracing
    // TODO: add auth
    let mix_node = MixNodeService;
    Server::builder().add_service(MixNodeServer::new(mix_node))
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

impl TryFrom<&proto::Ciphertext> for Ciphertext {
    type Error = MessageError;

    fn try_from(proto: &proto::Ciphertext) -> Result<Self, Self::Error> {
        Ok(Ciphertext::from((
            CompressedRistretto::from_slice(&proto.e)
                .decompress()
                .ok_or(MessageError::InvalidCiphertext)?,
            CompressedRistretto::from_slice(&proto.c)
                .decompress()
                .ok_or(MessageError::InvalidCiphertext)?,
        )))
    }
}

impl TryFrom<proto::Ciphertext> for Ciphertext {
    type Error = MessageError;

    fn try_from(proto: proto::Ciphertext) -> Result<Self, Self::Error> {
        TryFrom::try_from(&proto)
    }
}

impl TryFrom<&proto::EncryptedCodes> for EncryptedCodes {
    type Error = MessageError;

    fn try_from(proto: &proto::EncryptedCodes) -> Result<Self, Self::Error> {
        let proto::EncryptedCodes {
            x_code: x_proto,
            y_code: y_proto,
            enc_key,
        } = proto;

        let mut x_code: Vec<Ciphertext> = Vec::with_capacity(x_proto.len());
        for ct_proto in x_proto {
            let ct: Ciphertext = ct_proto.try_into()?;
            x_code.push(ct);
        }
        let mut y_code: Vec<Ciphertext> = Vec::with_capacity(y_proto.len());
        for ct_proto in y_proto {
            let ct: Ciphertext = ct_proto.try_into()?;
            y_code.push(ct);
        }
        let enc_key: Option<EncryptionKey> = match enc_key {
            Some(ek) => Some(EncryptionKey::from(
                CompressedRistretto::from_slice(ek)
                    .decompress()
                    .ok_or(MessageError::InvalidEncryptionKey)?,
            )),
            None => None,
        };

        Ok(Self {
            x_code,
            y_code,
            enc_key,
        })
    }
}

impl TryFrom<proto::EncryptedCodes> for EncryptedCodes {
    type Error = MessageError;

    fn try_from(proto: proto::EncryptedCodes) -> Result<Self, Self::Error> {
        TryFrom::try_from(&proto)
    }
}

impl From<&Ciphertext> for proto::Ciphertext {
    fn from(ct: &rust_elgamal::Ciphertext) -> Self {
        let (e, c) = ct.inner();
        Self {
            e: e.compress().to_bytes().to_vec(),
            c: c.compress().to_bytes().to_vec(),
        }
    }
}

impl From<Ciphertext> for proto::Ciphertext {
    fn from(ct: rust_elgamal::Ciphertext) -> Self {
        From::from(&ct)
    }
}

impl From<&EncryptedCodes> for proto::EncryptedCodes {
    fn from(codes: &EncryptedCodes) -> Self {
        let EncryptedCodes {
            x_code,
            y_code,
            enc_key,
        } = codes;

        Self {
            x_code: x_code.iter().map(proto::Ciphertext::from).collect(),
            y_code: y_code.iter().map(proto::Ciphertext::from).collect(),
            enc_key: enc_key.map(|ek| ek.as_ref().compress().to_bytes().to_vec()),
        }
    }
}

impl From<EncryptedCodes> for proto::EncryptedCodes {
    fn from(codes: EncryptedCodes) -> Self {
        let EncryptedCodes {
            x_code,
            y_code,
            enc_key,
        } = codes;

        Self {
            x_code: x_code.into_iter().map(proto::Ciphertext::from).collect(),
            y_code: y_code.into_iter().map(proto::Ciphertext::from).collect(),
            enc_key: enc_key.map(|ek| ek.as_ref().compress().to_bytes().to_vec()),
        }
    }
}

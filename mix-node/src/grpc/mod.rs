mod error;
mod middleware;
mod service;

use crate::{AppState, EncryptedCodes};
use error::MessageError;
use rust_elgamal::{Ciphertext, CompressedRistretto, EncryptionKey};
use service::MixNodeService;
use std::sync::Arc;
use tonic::transport::{server::Router, Server};

pub mod proto {
    tonic::include_proto!("mix_node");
}

pub fn app(state: AppState) -> Router {
    let state = Arc::new(state);
    let mix_node = proto::mix_node_server::MixNodeServer::with_interceptor(
        MixNodeService::new(Arc::clone(&state)),
        middleware::auth_middleware(state),
    );
    Server::builder().add_service(mix_node)
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

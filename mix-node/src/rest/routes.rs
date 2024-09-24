use super::error::Error;
use crate::{
    crypto::{Ciphertext, DecryptionShare},
    rokio, AppState, EncryptedCodes,
};
use anyhow::Context;
use axum::{extract::State, response::Json};
use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet};
use rayon::prelude::*;
use reqwest::Client;
use std::sync::Arc;

#[tracing::instrument(
        skip(_state, codes),
        fields(
            x_code.len = codes.x_code.len(),
            y_code.len = codes.y_code.len(),
            enc_key = ?codes.enc_key,
        )
    )]
pub async fn remix_handler(
    State(_state): State<Arc<AppState>>,
    Json(mut codes): Json<EncryptedCodes>,
) -> Result<Json<EncryptedCodes>, Error> {
    if codes.x_code.len() != codes.y_code.len() {
        return Err(Error::InvalidLength(
            "Codes have mismatched lengths.".to_owned(),
        ));
    }

    let codes = rokio::spawn(move || {
        remix::par::remix(
            &mut codes.x_code,
            &mut codes.y_code,
            codes.enc_key.as_ref().unwrap_or(crate::enc_key()),
        );
        codes
    })
    .await;

    Ok(Json(codes))
}

#[tracing::instrument(skip(state))]
pub async fn public_key_set(State(state): State<Arc<AppState>>) -> Json<PublicKeySet<Ristretto>> {
    Json(state.crypto.active_particiapnt.key_set().clone())
}

#[tracing::instrument(skip(state, plaintext))]
pub async fn encrypt(
    State(state): State<Arc<AppState>>,
    Json(plaintext): Json<Vec<u64>>,
) -> Json<Vec<Ciphertext>> {
    let ciphertexts = rokio::spawn(move || {
        let pub_key = state.crypto.active_particiapnt.key_set().shared_key();
        plaintext
            .into_par_iter()
            .map(|msg| {
                let mut rng = rand::thread_rng();
                pub_key.encrypt(msg, &mut rng)
            })
            .collect::<Vec<_>>()
    })
    .await;

    Json(ciphertexts)
}

#[tracing::instrument(skip(state))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Json(ciphertext): Json<Vec<Ciphertext>>,
) -> Json<Vec<DecryptionShare>> {
    let client = reqwest::Client::new();
    let mut dec_shares = vec![];
    for p in state.crypto.participants.iter() {
        // TODO: Use URL for participants
        let protocol = "http";
        let url = format!("{}://{}/elastic/decrypt-share", protocol, p.url);
        // TODO: parallelize this
        match request_share(&client, &url, &ciphertext).await {
            Ok(share) => dec_shares.push(share),
            Err(e) => {
                tracing::warn!("{e:?}");
                continue;
            }
        }
    }
    // ???: doesnt seem right
    let Json(my_share) = decrypt_share(State(state), Json(ciphertext)).await;
    dec_shares.push(my_share);

    Json(dec_shares)
}

pub async fn hamming_distance(
    State(_state): State<Arc<AppState>>,
    Json(_codes): Json<EncryptedCodes>,
) -> Result<Json<usize>, Error> {
    todo!()
}

async fn request_share(
    client: &Client,
    url: &str,
    ciphertext: &Vec<Ciphertext>,
) -> anyhow::Result<DecryptionShare> {
    client
        .post(url)
        .json(&ciphertext)
        .send()
        .await
        .with_context(|| format!("request to '{url}' failed"))?
        .json()
        .await
        .context("could not deserialize decryption share")
}

#[tracing::instrument(skip(state))]
pub async fn decrypt_share(
    State(state): State<Arc<AppState>>,
    Json(ciphertext): Json<Vec<Ciphertext>>,
) -> Json<DecryptionShare> {
    let share = rokio::spawn(move || {
        let active_participant = &state.crypto.active_particiapnt;
        let share = ciphertext
            .into_par_iter()
            .map(|msg| {
                let mut rng = rand::thread_rng();
                active_participant.decrypt_share(msg, &mut rng)
            })
            .collect::<Vec<_>>();
        DecryptionShare::new(active_participant.index(), share)
    })
    .await;

    Json(share)
}

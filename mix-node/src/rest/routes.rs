use super::error::Error;
use crate::{
    crypto::{self, Bits, Ciphertext, CryptoError, DecryptionShare},
    rokio, AppState, EncryptedCodes,
};
use anyhow::Context;
use axum::{extract::State, response::Json};
use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet};
use futures::FutureExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{field, Level, Span};

#[tracing::instrument(
        skip(state, codes),
        err(Debug, level = Level::ERROR),
        fields(
            x_code.len = codes.x_code.len(),
            y_code.len = codes.y_code.len(),
            enc_key,
        )
    )]
pub async fn remix_handler(
    State(state): State<Arc<AppState>>,
    Json(mut codes): Json<EncryptedCodes>,
) -> Result<Json<EncryptedCodes>, Error> {
    let codes = rokio::spawn(move || -> Result<_, CryptoError> {
        let enc_key = codes
            .enc_key
            .as_ref()
            .unwrap_or(state.pub_key_set().shared_key());
        Span::current().record("enc_key", field::debug(enc_key));

        crypto::remix(&mut codes.x_code, &mut codes.y_code, enc_key)?;
        Ok(codes)
    })
    .await?;

    Ok(Json(codes))
}

#[tracing::instrument(skip(state), ret(Debug, level = Level::TRACE))]
pub async fn public_key_set(State(state): State<Arc<AppState>>) -> Json<PublicKeySet<Ristretto>> {
    Json(state.pub_key_set().clone())
}

#[tracing::instrument(skip(state, bits), fields(
    pub_key,
    bits_len = bits.len(),
))]
pub async fn encrypt(
    State(state): State<Arc<AppState>>,
    Json(bits): Json<Bits>,
) -> Json<Vec<Ciphertext>> {
    let ciphertexts = rokio::spawn(move || {
        let pub_key = state.crypto.active_participant.key_set().shared_key();
        Span::current().record("pub_key", field::debug(pub_key));
        crypto::encrypt(pub_key, &bits)
    })
    .await;

    Json(ciphertexts)
}

#[tracing::instrument(skip(state, ciphertext), fields(
    ct_len = ciphertext.len(),
))]
pub async fn decrypt_share(
    State(state): State<Arc<AppState>>,
    Json(ciphertext): Json<Vec<Ciphertext>>,
) -> Json<DecryptionShare> {
    let share = rokio::spawn(move || {
        crypto::decryption_share_for(&state.crypto.active_participant, &ciphertext)
    })
    .await;

    Json(share)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HammingResponse {
    pub hamming_distance: usize,
}

#[tracing::instrument(skip(state, codes), ret(Debug, level = Level::TRACE), err(Debug, level = Level::ERROR), fields(hamming_distance))]
pub async fn hamming_distance(
    State(state): State<Arc<AppState>>,
    Json(codes): Json<EncryptedCodes>,
) -> Result<Json<HammingResponse>, Error> {
    let EncryptedCodes {
        mut x_code,
        mut y_code,
        ..
    } = codes;
    // Remix
    tracing::trace!("remix self");
    let (mut x_code, mut y_code) = {
        let state = Arc::clone(&state);
        rokio::spawn(move || -> Result<_, CryptoError> {
            crypto::remix(&mut x_code, &mut y_code, state.pub_key_set().shared_key())?;
            Ok((x_code, y_code))
        })
        .await?
    };
    // This algorithm runs serially and it's not fast to serialize and deserialize 2*25600 bits
    tracing::trace!("remix participants");
    for node in &state.crypto.participants {
        (x_code, y_code) = request_remix(
            &state.http_client,
            &node.url,
            x_code.clone(),
            y_code.clone(),
        )
        .await
        .unwrap_or((x_code, y_code));
        tracing::trace!(id = ?node, "remix participant");
    }

    let x_code = Arc::new(x_code);
    let y_code = Arc::new(y_code);

    // Decrypt
    tracing::trace!("request shares");
    let (x_shares, y_shares) = {
        let (x_inner_code, y_inner_code) = (Arc::clone(&x_code), Arc::clone(&y_code));

        let (mut x_shares, mut y_shares, x_self_share, y_self_share) = tokio::join!(
            request_all_shares(&x_code, &state),
            request_all_shares(&y_code, &state),
            {
                let state = Arc::clone(&state);
                rokio::spawn(move || {
                    crypto::decryption_share_for(&state.crypto.active_participant, &x_inner_code)
                })
            },
            {
                let state = Arc::clone(&state);
                rokio::spawn(move || {
                    crypto::decryption_share_for(&state.crypto.active_participant, &y_inner_code)
                })
            }
        );
        x_shares.push(x_self_share);
        y_shares.push(y_self_share);

        (x_shares, y_shares)
    };

    // Decrypt shares
    tracing::trace!("decrypt shares");
    let x_decrypt = {
        let state = Arc::clone(&state);
        rokio::spawn(move || crypto::decrypt_shares(state.pub_key_set(), &x_code, &x_shares))
    };
    let y_decrypt = {
        let state = Arc::clone(&state);
        rokio::spawn(move || crypto::decrypt_shares(state.pub_key_set(), &y_code, &y_shares))
    };
    let (x_decrypt, y_decrypt) = {
        let (x_decrypt, y_decrypt) = tokio::join!(x_decrypt, y_decrypt);
        (x_decrypt?, y_decrypt?)
    };

    // Hamming distance
    let hamming_distance = crypto::hamming_distance(x_decrypt, y_decrypt);
    Span::current().record("hamming_distance", hamming_distance);
    Ok(Json(HammingResponse { hamming_distance }))
}

async fn request_all_shares(
    code: &Arc<Vec<Ciphertext>>,
    state: &Arc<AppState>,
) -> Vec<DecryptionShare> {
    let mut request_futs = vec![];
    for p in state.crypto.participants.clone() {
        let client = state.http_client.clone();
        let code = Arc::clone(code);

        request_futs.push(async move { request_share(&client, &p.url, &code).await }.boxed());
    }

    let threshold = state.crypto.active_participant.key_set().params().threshold - 1; // assume this node computes its share

    let mut shares = vec![];
    while !request_futs.is_empty() && shares.len() < threshold {
        // PERF: instead of racing all the requests just race the minimum: threshold - shares.len()
        let (share_res, _, remaining_futs) = futures::future::select_all(request_futs).await;
        request_futs = remaining_futs;

        match share_res {
            Ok(s) => shares.push(s),
            _ => continue,
        }
    }

    shares
}

async fn request_remix(
    client: &Client,
    node_url: &str,
    x_code: Vec<Ciphertext>,
    y_code: Vec<Ciphertext>,
) -> anyhow::Result<(Vec<Ciphertext>, Vec<Ciphertext>)> {
    let response = network_request(
        client,
        &format!("{node_url}/remix"),
        &EncryptedCodes {
            x_code,
            y_code,
            enc_key: None,
        },
    )
    .await?;

    let EncryptedCodes { x_code, y_code, .. } = response
        .json()
        .await
        .context("could not deserialize decryption share")?;

    Ok((x_code, y_code))
}

async fn request_share(
    client: &Client,
    node_url: &str,
    ciphertext: &[Ciphertext],
) -> anyhow::Result<DecryptionShare> {
    network_request(client, &format!("{node_url}/decrypt-share"), ciphertext)
        .await?
        .json()
        .await
        .context("could not deserialize decryption share")
}

pub async fn network_request<T>(
    client: &Client,
    url: &str,
    body: &T,
) -> anyhow::Result<reqwest::Response>
where
    T: Serialize + ?Sized,
{
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .with_context(|| format!("failed sending request to '{url}'"))?
        .error_for_status()
        .context("error status code")?;

    if response.status() != reqwest::StatusCode::OK {
        anyhow::bail!(
            "request not 'OK' with status code {} and body: {:?}",
            response.status(),
            response.text().await
        );
    }

    Ok(response)
}

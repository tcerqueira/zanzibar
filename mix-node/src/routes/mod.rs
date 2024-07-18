use crate::rokio;
use axum::http::StatusCode;
use axum::response::Json;
use rust_elgamal::{Ciphertext, EncryptionKey};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedCodes {
    #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub x_code: Vec<Ciphertext>,
    #[serde(deserialize_with = "deserialize_vec_with_capacity")]
    pub y_code: Vec<Ciphertext>,
    pub enc_key: Option<EncryptionKey>,
}

#[tracing::instrument(
        skip(codes),
        fields(
            x_code.len = codes.x_code.len(),
            y_code.len = codes.y_code.len(),
            enc_key = ?codes.enc_key,
        )
    )]
pub async fn remix_handler(
    Json(mut codes): Json<EncryptedCodes>,
) -> Result<Json<EncryptedCodes>, (StatusCode, &'static str)> {
    if codes.x_code.len() != codes.y_code.len() {
        tracing::error!("length mismatch between codes");
        return Err((StatusCode::BAD_REQUEST, "Codes have mismatched lengths."));
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

    Ok(Json(codes))
}

fn deserialize_vec_with_capacity<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let mut vec = Vec::with_capacity(25600);
    Vec::deserialize_in_place(deserializer, &mut vec)?;
    Ok(vec)
}

use crate::{rokio, EncryptedCodes};
use axum::{http::StatusCode, response::Json};

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

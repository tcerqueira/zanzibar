mod common;

use bitvec::prelude::*;
use mix_node::{
    testing::{self, TestApp},
    EncryptedCodes,
};
use reqwest::StatusCode;
use std::{error::Error, iter};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_BITS: usize = common::N_BITS;

#[tokio::test]
async fn test_mix_node() -> Result<(), Box<dyn Error>> {
    let TestApp { port, .. } = testing::create_app(None).await;

    let (codes, dec_key) = common::set_up_payload();

    // Shuffle + Rerandomize + Serialization
    let client = reqwest::Client::new();
    let EncryptedCodes {
        x_code: enc_new_user,
        y_code: enc_archived_user,
        ..
    } = client
        .post(format!("http://localhost:{port}/remix"))
        .json(&codes)
        .send()
        .await?
        .json()
        .await?;

    // Decrypt
    let dec_new_user: BitVec<u8, Lsb0> = common::decrypt_bits(&enc_new_user, &dec_key).collect();
    let dec_archived_user: BitVec<u8, Lsb0> =
        common::decrypt_bits(&enc_archived_user, &dec_key).collect();

    // Assert result
    let hamming_distance = iter::zip(dec_new_user.iter(), dec_archived_user.iter())
        .filter(|(x, y)| x != y)
        .count();
    assert_eq!(hamming_distance, 0);
    assert_eq!(dec_new_user, dec_archived_user);
    assert_eq!(dec_new_user.count_ones(), N_BITS);
    assert_eq!(dec_archived_user.count_ones(), N_BITS);
    Ok(())
}

#[tokio::test]
async fn test_mix_node_bad_request() -> Result<(), Box<dyn Error>> {
    let TestApp { port, .. } = testing::create_app(None).await;

    let (mut codes, _dec_key) = common::set_up_payload();
    // Remove elements to cause a size mismatch
    codes.x_code.pop();
    codes.x_code.pop();

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://localhost:{port}/remix"))
        .json(&codes)
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn test_mix_node_unauthorized() -> Result<(), Box<dyn Error>> {
    let TestApp { port, .. } =
        testing::create_app(Some("test_mix_node_unauthorized".to_string())).await;

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://localhost:{port}/remix"))
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_mix_node_authorized() -> Result<(), Box<dyn Error>> {
    let auth_token = "test_mix_node_authorized";
    let TestApp { port, .. } = testing::create_app(Some(auth_token.to_string())).await;

    let (codes, _dec_key) = common::set_up_payload();

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://localhost:{port}/remix"))
        .header("Authorization", "Bearer ".to_string() + auth_token)
        .json(&codes)
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

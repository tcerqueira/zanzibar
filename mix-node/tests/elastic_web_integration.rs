mod common;

use bitvec::prelude::*;
use mix_node::{
    config::get_configuration,
    testing::{self, TestApp},
    ElasticEncryptedCodes,
};
use reqwest::StatusCode;
use std::{error::Error, iter};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_BITS: usize = common::N_BITS;

#[tokio::test]
async fn test_elastic_mix_node() -> Result<(), Box<dyn Error>> {
    let config = get_configuration()?;
    let TestApp { port, .. } = testing::create_app(config).await;

    let (codes, receiver) = common::set_up_elastic_payload();

    // Shuffle + Rerandomize + Serialization
    let client = reqwest::Client::new();
    let ElasticEncryptedCodes {
        x_code: enc_new_user,
        y_code: enc_archived_user,
        ..
    } = client
        .post(format!("http://localhost:{port}/elastic-remix"))
        .json(&codes)
        .send()
        .await?
        .json()
        .await?;

    // Decrypt
    let dec_new_user: BitVec<u8, Lsb0> =
        common::elastic_decrypt_bits(&enc_new_user, receiver.secret()).collect();
    let dec_archived_user: BitVec<u8, Lsb0> =
        common::elastic_decrypt_bits(&enc_archived_user, receiver.secret()).collect();

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
    let mut config = get_configuration()?;
    config.application.auth_token = None;
    let TestApp { port, .. } = testing::create_app(config).await;

    let (mut codes, _dec_key) = common::set_up_elastic_payload();
    // Remove elements to cause a size mismatch
    codes.x_code.pop();
    codes.x_code.pop();

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://localhost:{port}/elastic-remix"))
        .json(&codes)
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

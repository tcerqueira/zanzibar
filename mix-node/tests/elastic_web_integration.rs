mod common;

use bitvec::prelude::*;
use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet, Ciphertext};
use format as f;
use mix_node::{
    config::get_configuration,
    crypto::{self, DecryptionShare},
    test_helpers::{self, TestApp},
    ElasticEncryptedCodes,
};
use reqwest::StatusCode;
use std::iter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_BITS: usize = common::N_BITS;

#[tokio::test]
async fn test_elastic_mix_node() -> anyhow::Result<()> {
    let config = get_configuration()?;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let (codes, receiver) = common::set_up_elastic_payload();

    // Shuffle + Rerandomize + Serialization
    let client = reqwest::Client::new();
    let ElasticEncryptedCodes {
        x_code: enc_new_user,
        y_code: enc_archived_user,
        ..
    } = client
        .post(f!("http://localhost:{port}/elastic/remix"))
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
async fn test_mix_node_bad_request() -> anyhow::Result<()> {
    let mut config = get_configuration()?;
    config.application.auth_token = None;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let (mut codes, _dec_key) = common::set_up_elastic_payload();
    // Remove elements to cause a size mismatch
    codes.x_code.pop();
    codes.x_code.pop();

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/elastic/remix"))
        .json(&codes)
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn test_mix_node_public_key() -> anyhow::Result<()> {
    let config = get_configuration()?;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let client = reqwest::Client::new();
    let response = client
        .get(f!("http://localhost:{port}/elastic/public-key-set"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let _body: PublicKeySet<Ristretto> = response.json().await?;

    Ok(())
}

#[tokio::test]
async fn test_mix_node_encrypt() -> anyhow::Result<()> {
    let config = get_configuration()?;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let payload: Vec<_> = (0..10u64).collect();

    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/elastic/encrypt"))
        .json(&payload)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body: Vec<Ciphertext<Ristretto>> = response.json().await?;

    assert_eq!(payload.len(), body.len());

    Ok(())
}

#[tokio::test]
async fn test_network_of_mix_nodes() -> anyhow::Result<()> {
    let nodes = test_helpers::create_network(3, 2).await;

    // Request public key
    let client = reqwest::Client::new();
    let response = client
        .get(f!(
            "http://localhost:{}/elastic/public-key-set",
            nodes[0].port
        ))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // Encrypt client side
    let mut rng = rand::thread_rng();
    let payload: Vec<_> = (0..8u64).collect();
    let pub_key: PublicKeySet<Ristretto> = response.json().await?;
    let encrypted: Vec<_> = payload
        .iter()
        .map(|pt| pub_key.shared_key().encrypt(*pt, &mut rng))
        .collect();

    // Decrypt
    let mut shares = vec![];
    for TestApp { port, .. } in nodes {
        let response = client
            .post(f!("http://localhost:{port}/elastic/decrypt-share"))
            .json(&encrypted)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let share: DecryptionShare = response.json().await?;
        shares.push(share);
    }

    let decrypted = crypto::decrypt_shares(pub_key, encrypted, shares).expect("failed to decrypt");
    assert_eq!(payload, decrypted);
    Ok(())
}

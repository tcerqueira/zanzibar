mod common;

use bitvec::prelude::*;
use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet, Ciphertext};
use format as f;
use mix_node::{
    config::get_configuration,
    crypto::{self, Bits, DecryptionShare},
    rest::routes::HammingResponse,
    test_helpers::{self, TestApp},
    EncryptedCodes,
};
use reqwest::StatusCode;
use secrecy::Secret;
use std::iter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const N_BITS: usize = common::N_BITS;

#[tokio::test]
async fn test_mix_node() -> anyhow::Result<()> {
    let config = get_configuration()?;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let (codes, receiver) = common::set_up_payload();

    // Shuffle + Rerandomize + Serialization
    let client = reqwest::Client::new();
    let EncryptedCodes {
        x_code: enc_new_user,
        y_code: enc_archived_user,
        ..
    } = client
        .post(f!("http://localhost:{port}/remix"))
        .json(&codes)
        .send()
        .await?
        .json()
        .await?;

    // Decrypt
    let dec_new_user: Bits = common::decrypt_bits(&enc_new_user, receiver.secret()).collect();
    let dec_archived_user: Bits =
        common::decrypt_bits(&enc_archived_user, receiver.secret()).collect();

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

    // let code = common::set_up_iris_code(mix_node::N_BITS);

    let (mut codes, _receiver) = common::set_up_payload();
    // Remove elements to cause a size mismatch
    codes.x_code.pop();
    codes.x_code.pop();

    // Bad request + Serialization
    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/remix"))
        .json(&codes)
        .send()
        .await?;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn test_mix_node_unauthorized() -> anyhow::Result<()> {
    let mut config = get_configuration()?;
    config.application.auth_token = Some(Secret::new("test_mix_node_unauthorized".to_string()));
    let TestApp { port, .. } = test_helpers::create_app(config).await;

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
async fn test_mix_node_authorized() -> anyhow::Result<()> {
    let auth_token = "test_mix_node_authorized";
    let mut config = get_configuration()?;
    config.application.auth_token = Some(Secret::new(auth_token.to_string()));
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let (codes, _receiver) = common::set_up_payload();

    // Auth
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

#[tokio::test]
async fn test_mix_node_public_key() -> anyhow::Result<()> {
    let config = get_configuration()?;
    let TestApp { port, .. } = test_helpers::create_app(config).await;

    let client = reqwest::Client::new();
    let response = client
        .get(f!("http://localhost:{port}/public-key-set"))
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

    let payload = common::set_up_iris_code(mix_node::N_BITS);

    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/encrypt"))
        .json(&payload)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body: Vec<Ciphertext<Ristretto>> = response.json().await?;

    assert_eq!(payload.len(), body.len());
    Ok(())
}

#[tokio::test]
async fn test_network_decrypt_shares() -> anyhow::Result<()> {
    let nodes = test_helpers::create_network(3, 2).await;

    // Request public key
    let client = reqwest::Client::new();
    let response = client
        .get(f!("http://localhost:{}/public-key-set", nodes[0].port))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // Encrypt server side
    let payload: Bits = bitvec![0, 1, 0, 1, 1, 0, 0, 1];

    let pub_key: PublicKeySet<Ristretto> = response.json().await?;
    let encrypted: Vec<_> = client
        .post(f!("http://localhost:{}/encrypt", nodes[0].port))
        .json(&payload)
        .send()
        .await?
        .json()
        .await?;

    // Decrypt
    let mut shares = vec![];
    for TestApp { port, .. } in nodes.into_iter().take(2) {
        let response = client
            .post(f!("http://localhost:{port}/decrypt-share"))
            .json(&encrypted)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let share: DecryptionShare = response.json().await?;
        shares.push(share);
    }

    let decrypted =
        crypto::decrypt_shares(&pub_key, &encrypted, &shares).expect("failed to decrypt");
    assert_eq!(payload, decrypted);
    Ok(())
}

#[tokio::test]
async fn test_network_hamming_distance() -> anyhow::Result<()> {
    let [TestApp { port, .. }, ..] = test_helpers::create_network(3, 2).await[..] else {
        return Err(anyhow::anyhow!("needs at least one node"));
    };

    // Request public key
    let client = reqwest::Client::new();
    let response = client
        .get(f!("http://localhost:{}/public-key-set", port))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let pub_key: PublicKeySet<Ristretto> = response.json().await?;

    // Codes are the same, expected hamming distance = 0
    let payload = {
        let code = crypto::encrypt(
            pub_key.shared_key(),
            &common::set_up_iris_code(mix_node::N_BITS),
        );
        EncryptedCodes {
            x_code: code.clone(),
            y_code: code,
            enc_key: Some(pub_key.shared_key().clone()),
        }
    };

    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/hamming"))
        .json(&payload)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let HammingResponse { hamming_distance } = response.json().await?;
    assert_eq!(hamming_distance, 0);

    Ok(())
}

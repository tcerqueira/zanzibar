use elastic_elgamal::{group::Ristretto, sharing::PublicKeySet};
use format as f;
use mix_node::{
    crypto::{self, Bits},
    rest::routes::HammingResponse,
    EncryptedCodes,
};
use rand::Rng;
use reqwest::StatusCode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Set up");
    let n_bits = std::env::args()
        .nth(1)
        .expect("cli arg 'n_bits' missing")
        .parse::<usize>()
        .expect("cli arg is not a number")
        * 2;
    let port = 6000;
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
        let code = crypto::encrypt(pub_key.shared_key(), &set_up_iris_code(n_bits));
        EncryptedCodes {
            x_code: code.clone(),
            y_code: code,
            enc_key: Some(pub_key.shared_key().clone()),
        }
    };

    println!("Request sent");
    let client = reqwest::Client::new();
    let response = client
        .post(f!("http://localhost:{port}/hamming"))
        .json(&payload)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let HammingResponse { hamming_distance } = response.json().await?;
    println!("hamming distane: {hamming_distance}");

    Ok(())
}

pub fn set_up_iris_code(size: usize) -> Bits {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen::<bool>()).collect::<Bits>()
}

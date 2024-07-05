use bitvec::prelude::*;
use lambda::mix_node::EncryptedCodes;
use lambda::testing::{self, TestApp};
use rand::{CryptoRng, Rng};
use reqwest::StatusCode;
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};
use std::{error::Error, iter};

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

const N_BITS: usize = lambda::N_BITS / 2;

fn set_up_payload() -> (EncryptedCodes, DecryptionKey) {
    let mut rng = rand::thread_rng();
    let new_iris_code = BitVec::<_, Lsb0>::from_slice(&rng.gen::<[u8; N_BITS / 8]>());
    let archived_iris_code = new_iris_code.clone();

    // Encode bits
    let mut new_user: BitVec<u8, Lsb0> = BitVec::with_capacity(N_BITS * 2);
    new_user.extend(encode_bits(&new_iris_code[..]));
    let mut archived_user: BitVec<u8, Lsb0> = BitVec::with_capacity(N_BITS * 2);
    archived_user.extend(encode_bits(&archived_iris_code[..]));

    // Encrypt
    let dec_key = DecryptionKey::new(&mut rng);
    let enc_key = dec_key.encryption_key();

    let enc_new_user: Vec<_> = encrypt_bits(&new_user[..], enc_key, &mut rng).collect();
    let enc_archived_user: Vec<_> = encrypt_bits(&archived_user[..], enc_key, &mut rng).collect();

    (
        EncryptedCodes {
            x_code: enc_new_user,
            y_code: enc_archived_user,
            enc_key: Some(*enc_key),
        },
        dec_key,
    )
}

#[tokio::test]
async fn test_mix_node() -> Result<(), Box<dyn Error>> {
    let TestApp { port, .. } = testing::create_app().await;

    let (codes, dec_key) = set_up_payload();

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
    let dec_new_user: BitVec<u8, Lsb0> = decrypt_bits(&enc_new_user, &dec_key).collect();
    let dec_archived_user: BitVec<u8, Lsb0> = decrypt_bits(&enc_archived_user, &dec_key).collect();

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
    let TestApp { port, .. } = testing::create_app().await;

    let (mut codes, _dec_key) = set_up_payload();
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

#[test]
fn test_encode_bits() {
    let bits = BitVec::<u8, Msb0>::from_slice(&[0b11100100]);
    let expected = BitVec::<u8, Msb0>::from_slice(&[0b10101001, 0b01100101]);

    let enc_bits: BitVec<u8, Lsb0> = encode_bits(&bits[..]).collect();

    assert_eq!(enc_bits, expected);
}

#[test]
fn test_decode_bits() {
    let bits = BitVec::<u8, Msb0>::from_slice(&[0b11100100]);
    let enc_bits: BitVec<u8, Lsb0> = encode_bits(&bits[..]).collect();

    let dec_bits: BitVec<u8, Msb0> = decode_bits(&enc_bits[..]).collect();
    assert_eq!(bits, dec_bits);
}

fn encode_bits<T: BitStore, O: BitOrder>(bits: &BitSlice<T, O>) -> impl Iterator<Item = bool> + '_ {
    bits.iter().flat_map(|bit| {
        let encoding = match *bit {
            false /*0*/ => (false, true) /*01*/,
            true  /*1*/ => (true, false) /*10*/,
        };
        iter::once(encoding.0).chain(iter::once(encoding.1))
    })
}

fn encrypt_bits<'a, T: BitStore, O: BitOrder>(
    bits: &'a BitSlice<T, O>,
    ek: &'a EncryptionKey,
    rng: &'a mut (impl Rng + CryptoRng + 'static),
) -> impl Iterator<Item = Ciphertext> + 'a {
    bits.iter()
        .map(|bit| ek.encrypt(&Scalar::from(*bit as u32) * &GENERATOR_TABLE, rng))
}

fn decrypt_bits<'a>(
    ct: &'a [Ciphertext],
    pk: &'a DecryptionKey,
) -> impl Iterator<Item = bool> + 'a {
    ct.iter().map(|ct| {
        let point = pk.decrypt(*ct);
        point != (&Scalar::from(0u32) * &GENERATOR_TABLE)
    })
}

fn decode_bits<T: BitStore, O: BitOrder>(bits: &BitSlice<T, O>) -> impl Iterator<Item = bool> + '_ {
    bits.chunks_exact(2).map(|bit_pair| {
        let bit_pair = (bit_pair[0], bit_pair[1]);
        match bit_pair {
            (false, true)   /*01*/ => false /*0*/,
            (true, false)   /*10*/ => true  /*1*/,
            other => panic!("invalid encoding of bit: {other:?}")
        }
    })
}

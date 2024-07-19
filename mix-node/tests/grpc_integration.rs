mod common;

use bitvec::prelude::*;
use mix_node::grpc::proto;
use mix_node::grpc::proto::mix_node_client::MixNodeClient;
use mix_node::routes::EncryptedCodes;
use mix_node::testing::{self, TestApp};
use std::{error::Error, iter};
use tonic::Code;

use mimalloc::MiMalloc as GlobalAllocator;

#[global_allocator]
static GLOBAL: GlobalAllocator = GlobalAllocator;

const N_BITS: usize = common::N_BITS;

#[tokio::test]
async fn test_mix_node() -> Result<(), Box<dyn Error>> {
    let TestApp { port, .. } = testing::create_grpc().await;

    let (codes, dec_key) = common::set_up_payload();

    // Shuffle + Rerandomize + Serialization
    let mut client = MixNodeClient::connect(format!("http://localhost:{port}")).await?;
    let proto_codes: proto::EncryptedCodes = codes.into();
    let EncryptedCodes {
        x_code: enc_new_user,
        y_code: enc_archived_user,
        ..
    } = client.remix(proto_codes).await?.into_inner().try_into()?;

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
    let TestApp { port, .. } = testing::create_grpc().await;

    let (mut codes, _dec_key) = common::set_up_payload();
    // Remove elements to cause a size mismatch
    codes.x_code.pop();
    codes.x_code.pop();

    // Bad request + Serialization
    let mut client = MixNodeClient::connect(format!("http://localhost:{port}")).await?;
    let proto_codes: proto::EncryptedCodes = codes.into();
    let response = client.remix(proto_codes).await.unwrap_err();

    // Assert
    assert_eq!(response.code(), Code::InvalidArgument);
    Ok(())
}

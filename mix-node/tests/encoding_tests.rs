mod common;

use bitvec::prelude::*;

#[test]
fn test_encode_bits() {
    let bits = bitvec![1, 1, 1, 0, 0, 1, 0, 0];
    let expected = bitvec![1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1];

    let enc_bits: BitVec = common::encode_bits(&bits[..]).collect();

    assert_eq!(enc_bits, expected);
}

#[test]
fn test_decode_bits() {
    let bits = bitvec![1, 1, 1, 0, 0, 1, 0, 0];
    let enc_bits = bitvec![1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1];

    let dec_bits: BitVec = common::decode_bits(&enc_bits[..]).collect();
    assert_eq!(bits, dec_bits);
}

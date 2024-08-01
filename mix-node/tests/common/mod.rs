use bitvec::prelude::*;
use mix_node::EncryptedCodes;
use rand::{CryptoRng, Rng};
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};
use std::iter;

pub const N_BITS: usize = mix_node::N_BITS / 2;

pub fn set_up_payload() -> (EncryptedCodes, DecryptionKey) {
    let mut rng = rand::thread_rng();
    let new_iris_code = BitVec::<_, Lsb0>::from_slice(&rng.gen::<[u8; N_BITS / 8]>());
    let archived_iris_code = new_iris_code.clone();

    // Encode bits
    let mut new_user: BitVec = BitVec::with_capacity(N_BITS * 2);
    new_user.extend(encode_bits(&new_iris_code[..]));
    let mut archived_user: BitVec = BitVec::with_capacity(N_BITS * 2);
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

pub fn encode_bits<T: BitStore, O: BitOrder>(
    bits: &BitSlice<T, O>,
) -> impl Iterator<Item = bool> + '_ {
    bits.iter().flat_map(|bit| {
        let encoding = match *bit {
            false /*0*/ => (false, true) /*01*/,
            true  /*1*/ => (true, false) /*10*/,
        };
        iter::once(encoding.0).chain(iter::once(encoding.1))
    })
}

#[allow(dead_code)]
pub fn encrypt_bits<'a, T: BitStore, O: BitOrder>(
    bits: &'a BitSlice<T, O>,
    ek: &'a EncryptionKey,
    rng: &'a mut (impl Rng + CryptoRng + 'static),
) -> impl Iterator<Item = Ciphertext> + 'a {
    bits.iter()
        .map(|bit| ek.encrypt(&Scalar::from(*bit as u32) * &GENERATOR_TABLE, rng))
}

#[allow(dead_code)]
pub fn decrypt_bits<'a>(
    ct: &'a [Ciphertext],
    pk: &'a DecryptionKey,
) -> impl Iterator<Item = bool> + 'a {
    ct.iter().map(|ct| {
        let point = pk.decrypt(*ct);
        point != (&Scalar::from(0u32) * &GENERATOR_TABLE)
    })
}

pub fn decode_bits<T: BitStore, O: BitOrder>(
    bits: &BitSlice<T, O>,
) -> impl Iterator<Item = bool> + '_ {
    bits.chunks_exact(2).map(|bit_pair| {
        let bit_pair = (bit_pair[0], bit_pair[1]);
        match bit_pair {
            (false, true)   /*01*/ => false /*0*/,
            (true, false)   /*10*/ => true  /*1*/,
            other => panic!("invalid encoding of bit: {other:?}")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_bits() {
        let bits = bitvec![1, 1, 1, 0, 0, 1, 0, 0];
        let expected = bitvec![1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1];

        let enc_bits: BitVec = encode_bits(&bits[..]).collect();

        assert_eq!(enc_bits, expected);
    }

    #[test]
    fn test_decode_bits() {
        let bits = bitvec![1, 1, 1, 0, 0, 1, 0, 0];
        let enc_bits = bitvec![1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1];

        let dec_bits: BitVec = decode_bits(&enc_bits[..]).collect();
        assert_eq!(bits, dec_bits);
    }
}

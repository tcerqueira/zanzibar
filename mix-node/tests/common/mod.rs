use bitvec::prelude::*;
use rand::{CryptoRng, Rng};
use rust_elgamal::{Ciphertext, DecryptionKey, EncryptionKey, Scalar, GENERATOR_TABLE};
use std::iter;

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
}

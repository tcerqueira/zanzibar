use bitvec::prelude::*;
use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Keypair, PublicKey, SecretKey};
use mix_node::{crypto::Ciphertext, EncryptedCodes};
use rand::{CryptoRng, Rng};
use std::iter;

pub const N_BITS: usize = mix_node::N_BITS / 2;

#[allow(unused)]
pub fn set_up_payload() -> (EncryptedCodes, Keypair<Ristretto>) {
    let mut rng = rand::thread_rng();
    let new_iris_code = BitVec::<_, Lsb0>::from_slice(&rng.gen::<[u8; N_BITS / 8]>());
    let archived_iris_code = new_iris_code.clone();

    // Encode bits
    let mut new_user: BitVec = BitVec::with_capacity(N_BITS * 2);
    new_user.extend(encode_bits(&new_iris_code[..]));
    let mut archived_user: BitVec = BitVec::with_capacity(N_BITS * 2);
    archived_user.extend(encode_bits(&archived_iris_code[..]));

    // Encrypt
    let receiver = Keypair::generate(&mut rng);
    let dec_key = receiver.secret().clone();
    let enc_key = receiver.public().clone();

    let enc_new_user: Vec<_> = encrypt_bits(&new_user[..], &enc_key, &mut rng).collect();
    let enc_archived_user: Vec<_> = encrypt_bits(&archived_user[..], &enc_key, &mut rng).collect();

    (
        EncryptedCodes {
            x_code: enc_new_user,
            y_code: enc_archived_user,
            enc_key: Some(enc_key),
        },
        receiver,
    )
}

#[allow(unused)]
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

#[allow(unused)]
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

#[allow(unused)]
pub fn encrypt_bits<'a, T: BitStore, O: BitOrder>(
    bits: &'a BitSlice<T, O>,
    ek: &'a PublicKey<Ristretto>,
    rng: &'a mut (impl Rng + CryptoRng + 'static),
) -> impl Iterator<Item = Ciphertext> + 'a {
    bits.iter().map(|bit| ek.encrypt(*bit as u32, rng))
}

#[allow(unused)]
pub fn decrypt_bits<'a>(
    ct: &'a [Ciphertext],
    pk: &'a SecretKey<Ristretto>,
) -> impl Iterator<Item = bool> + 'a {
    ct.iter().map(|ct| {
        let point = pk.decrypt(*ct, &DiscreteLogTable::new(0..2)).unwrap();
        point != 0u64
    })
}

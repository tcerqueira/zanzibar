//! Secure cryptographic primitives for threshold ElGamal encryption.
//!
//! This module provides a set of tools for encrypted communication with threshold
//! decryption capabilities using the ElGamal cryptosystem over the Ristretto curve.
//! The implementation supports distributed key generation, encryption, remixing,
//! threshold decryption, and verification of decryption shares.
//!
//! # Key Features
//!
//! * Secure threshold encryption using ElGamal over Ristretto
//! * Efficient parallel processing with Rayon
//! * Verifiable decryption shares
//! * Support for mixing and remixing of ciphertexts
//! * Hamming distance calculation between bit vectors
//!
//! # Examples
//!
//! ```
//! # use anyhow::Result;
//! # use elastic_elgamal::sharing::{Dealer, Params, PublicKeySet, ActiveParticipant};
//! # use elastic_elgamal::group::Ristretto;
//! # use bitvec::prelude::*;
//! # use mix_node::crypto::*;
//! # fn main() -> Result<()> {
//! # let mut rng = rand::thread_rng();
//! # let params = Params::new(3, 2);
//! # let dealer = Dealer::<Ristretto>::new(params, &mut rng);
//! # let (public_poly, poly_proof) = dealer.public_info();
//! # let key_set = PublicKeySet::new(params, public_poly, poly_proof)?;
//! # let participants: Vec<_> = (0..3)
//! #    .map(|i| ActiveParticipant::new(key_set.clone(), i,
//! #         dealer.secret_share_for_participant(i)).unwrap())
//! #    .collect();
//! # let bits = bitvec![1, 0, 1, 0];
//! // Encrypt data
//! let encrypted = encrypt(key_set.shared_key(), &bits);
//!
//! // Generate decryption shares
//! let shares = vec![
//!     decryption_share_for(&participants[0], &encrypted),
//!     decryption_share_for(&participants[1], &encrypted),
//! ];
//!
//! // Combine shares and decrypt
//! let decrypted = decrypt_shares(&key_set, &encrypted, &shares)?;
//! # Ok(())
//! # }
//! ```

use anyhow::Context;
use elastic_elgamal::{
    group::Ristretto,
    sharing::{ActiveParticipant, PublicKeySet},
    CandidateDecryption, DiscreteLogTable, LogEqualityProof, PublicKey, VerifiableDecryption,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use thiserror::Error;

/// An ElGamal ciphertext over the Ristretto curve.
pub type Ciphertext = elastic_elgamal::Ciphertext<Ristretto>;

/// A bit vector used for storing binary data.
pub type Bits = bitvec::vec::BitVec;

/// A decryption share from a participant in the threshold encryption scheme.
///
/// Contains the participant's index and their decryption shares
/// for a set of ciphertexts, along with proofs of correctness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    index: usize,
    share: Vec<(VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>)>,
}

impl DecryptionShare {
    /// Creates a new decryption share with the given participant index and shares.
    ///
    /// # Arguments
    ///
    /// * `index` - The participant's index
    /// * `share` - A vector of verifiable decryptions with their proofs
    ///
    /// # Returns
    ///
    /// A new `DecryptionShare` instance
    pub fn new(
        index: usize,
        share: Vec<(VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>)>,
    ) -> Self {
        Self { index, share }
    }
}

/// Discrete logarithm lookup table optimized for binary values.
///
/// This static table is used for efficient decryption of binary values (0 or 1).
pub static LOOKUP_TABLE: LazyLock<DiscreteLogTable<Ristretto>> =
    LazyLock::new(|| DiscreteLogTable::<Ristretto>::new(0..=1));

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Error indicating invalid or mismatched lengths in cryptographic operations.
    #[error("InvalidLength: {0}")]
    InvalidLength(String),
}

/// Remixes two ciphertext vectors using ElGamal homomorphic properties.
///
/// This function performs remixing operations on two encrypted code vectors.
/// Both vectors must have the same length, and the length must be even.
pub fn remix(
    x_code: &mut [Ciphertext],
    y_code: &mut [Ciphertext],
    pub_key: &PublicKey<Ristretto>,
) -> Result<(), CryptoError> {
    if x_code.len() != y_code.len() || x_code.len() % 2 == 1 {
        return Err(CryptoError::InvalidLength(
            "Codes have invalid lengths. Either mismatched or odd length.".to_owned(),
        ));
    }

    remix::par::remix(x_code, y_code, pub_key);
    Ok(())
}

/// Encrypts a bit vector using the provided public key.
///
/// This function encrypts each bit in the input bit vector in parallel
/// using the ElGamal encryption scheme.
pub fn encrypt(pub_key: &PublicKey<Ristretto>, bits: &Bits) -> Vec<Ciphertext> {
    bits.as_raw_slice()
        .into_par_iter()
        .enumerate()
        .flat_map(|(chunk_idx, &chunk)| {
            let chunk_size = 8 * std::mem::size_of_val(&chunk);
            let start_bit = chunk_idx * chunk_size;
            let end_bit = std::cmp::min(start_bit + chunk_size, bits.len());

            (0..end_bit - start_bit)
                .into_par_iter()
                .map(move |bit_offset| {
                    let mut rng = rand::thread_rng();
                    let bit = (chunk >> bit_offset) & 1;
                    pub_key.encrypt(bit as u64, &mut rng)
                })
        })
        .collect::<Vec<_>>()
}

/// Generates decryption shares for a set of ciphertexts.
///
/// This function allows a participant to generate their decryption share
/// for each ciphertext in the provided array.
pub fn decryption_share_for(
    active_participant: &ActiveParticipant<Ristretto>,
    ciphertext: &[Ciphertext],
) -> DecryptionShare {
    let share = ciphertext
        .par_iter()
        .map(|msg| {
            let mut rng = rand::thread_rng();
            active_participant.decrypt_share(*msg, &mut rng)
        })
        .collect::<Vec<_>>();
    DecryptionShare::new(active_participant.index(), share)
}

/// Combines decryption shares to recover the original plaintext.
///
/// This function verifies and combines decryption shares from multiple
/// participants to decrypt the original message.
pub fn decrypt_shares(
    key_set: &PublicKeySet<Ristretto>,
    enc: &[Ciphertext],
    shares: &[DecryptionShare],
) -> anyhow::Result<Bits> {
    if shares.iter().any(|s| s.share.len() != enc.len()) {
        anyhow::bail!("mismatch of lengths between encrypted ciphertext a decryption shares");
    }
    // Transpose vectors
    let transposed = (0..enc.len()).into_par_iter().map(|ct_idx| {
        shares
            .into_par_iter()
            .map(move |s| (s.index, s.share[ct_idx]))
    });

    transposed
        .zip(enc)
        .map(|(shares, enc)| {
            let dec_iter: Vec<_> = shares
                .filter_map(|(i, (share, proof))| {
                    let share = CandidateDecryption::from_bytes(&share.to_bytes())?;
                    let verification = key_set.verify_share(share, *enc, i, &proof).ok()?;
                    Some((i, verification))
                })
                .collect();
            let combined = key_set
                .params()
                .combine_shares(dec_iter.into_iter())
                .context("failed to combine shares")?;
            Ok(combined
                .decrypt(*enc, &LOOKUP_TABLE)
                .context("decrypted values out of range of lookup table")?
                == 1u64)
        })
        // PERF: collect directly to BitVec
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Bits::from_iter)
}

/// Calculates the Hamming distance between two bit vectors.
///
/// The Hamming distance is the number of positions at which the corresponding
/// bits are different.
pub fn hamming_distance(x_code: Bits, y_code: Bits) -> usize {
    // Q: What if x and y are different sizes?
    (x_code ^ y_code).count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;

    use elastic_elgamal::sharing::{ActiveParticipant, Dealer, Params};
    use rand::{CryptoRng, Rng};

    fn setup(
        shares: usize,
        threshold: usize,
    ) -> (
        PublicKeySet<Ristretto>,
        Dealer<Ristretto>,
        (impl Rng + CryptoRng),
    ) {
        let mut rng = rand::thread_rng();
        let params = Params::new(shares, threshold);

        // Initialize the dealer.
        let dealer = Dealer::<Ristretto>::new(params, &mut rng);
        let (public_poly, poly_proof) = dealer.public_info();
        (
            PublicKeySet::new(params, public_poly, poly_proof).unwrap(),
            dealer,
            rng,
        )
    }

    #[test]
    fn test_protocol() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);

        let participants: Vec<_> = (0..3)
            .map(|i| {
                ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i))
                    .unwrap()
            })
            .collect();

        let x_payload: Vec<_> = [0, 1, 0, 1, 0, 1u64].to_vec();
        let y_payload: Vec<_> = [1, 1, 0, 1, 0, 1u64].to_vec();
        // Encrypt
        let mut x_ct = x_payload
            .iter()
            .map(|msg| key_set.shared_key().encrypt(*msg, &mut rng))
            .collect::<Vec<_>>();
        let mut y_ct = y_payload
            .iter()
            .map(|msg| key_set.shared_key().encrypt(*msg, &mut rng))
            .collect::<Vec<_>>();
        // Remix
        for _ in 0..3 {
            remix(&mut x_ct, &mut y_ct, key_set.shared_key())?;
        }
        // Decrypt
        let x_shares: Vec<_> = participants
            .iter()
            .skip(1)
            .take(2)
            .map(|p| decryption_share_for(p, &x_ct))
            .collect();
        let y_shares: Vec<_> = participants
            .iter()
            .take(2)
            .map(|p| decryption_share_for(p, &y_ct))
            .collect();

        let x_decrypted = decrypt_shares(&key_set, &x_ct, &x_shares)?;
        let y_decrypted = decrypt_shares(&key_set, &y_ct, &y_shares)?;

        assert_eq!(hamming_distance(x_decrypted, y_decrypted), 1);
        Ok(())
    }

    #[test]
    fn test_decrypt_shares() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);
        let plaintext = 1u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let shares: Vec<_> = (0..3)
            .map(|i| {
                let p = ActiveParticipant::new(
                    key_set.clone(),
                    i,
                    dealer.secret_share_for_participant(i),
                )
                .unwrap();

                let share = p.decrypt_share(encrypted, &mut rng);
                DecryptionShare::new(i, vec![share])
            })
            .collect();

        let decrypted = decrypt_shares(&key_set, &[encrypted], &shares).unwrap();
        assert_eq!(decrypted[0] as u64, plaintext);
        Ok(())
    }

    #[test]
    fn test_decrypt_empty() -> anyhow::Result<()> {
        let (key_set, ..) = setup(3, 2);

        let shares: Vec<_> = (0..2).map(|i| DecryptionShare::new(i, vec![])).collect();

        let decrypted = decrypt_shares(&key_set, &[], &shares).unwrap();
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[test]
    fn test_decrypt_no_shares() -> anyhow::Result<()> {
        let (key_set, _dealer, mut rng) = setup(3, 2);

        let plaintext = 5u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let decrypted = decrypt_shares(&key_set, &[encrypted], &[]);
        assert!(decrypted.is_err());
        Ok(())
    }

    #[test]
    fn test_decrypt_enough_shares() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);

        let plaintext = 1u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let shares: Vec<_> = (0..2)
            .map(|i| {
                let p = ActiveParticipant::new(
                    key_set.clone(),
                    i,
                    dealer.secret_share_for_participant(i),
                )
                .unwrap();

                let share = p.decrypt_share(encrypted, &mut rng);
                DecryptionShare::new(i, vec![share])
            })
            .collect();

        let decrypted = decrypt_shares(&key_set, &[encrypted], &shares).unwrap();
        assert_eq!(decrypted[0] as u64, plaintext);
        Ok(())
    }

    #[test]
    fn test_decrypt_not_enough_shares() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);

        let plaintext = 5u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let shares: Vec<_> = (0..1)
            .map(|i| {
                let p = ActiveParticipant::new(
                    key_set.clone(),
                    i,
                    dealer.secret_share_for_participant(i),
                )
                .unwrap();

                let share = p.decrypt_share(encrypted, &mut rng);
                DecryptionShare::new(i, vec![share])
            })
            .collect();

        let decrypted = decrypt_shares(&key_set, &[encrypted], &shares);
        assert!(decrypted.is_err());
        Ok(())
    }

    #[test]
    fn test_decrypt_mismatch_len() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let params = Params::new(3, 2);

        // Initialize the dealer.
        let dealer = Dealer::<Ristretto>::new(params, &mut rng);
        let (public_poly, poly_proof) = dealer.public_info();
        let key_set = PublicKeySet::new(params, public_poly, poly_proof)?;

        let plaintext = 5u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let shares: Vec<_> = (0..3)
            .map(|i| {
                let p = ActiveParticipant::new(
                    key_set.clone(),
                    i,
                    dealer.secret_share_for_participant(i),
                )
                .unwrap();

                let _share = p.decrypt_share(encrypted, &mut rng);
                DecryptionShare::new(i, vec![])
            })
            .collect();

        let decrypted = decrypt_shares(&key_set, &[encrypted], &shares);
        assert!(decrypted.is_err());
        Ok(())
    }
}

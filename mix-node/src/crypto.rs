use elastic_elgamal::{
    group::Ristretto, sharing::PublicKeySet, CandidateDecryption, Ciphertext, DiscreteLogTable,
    LogEqualityProof, VerifiableDecryption,
};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionShare {
    index: usize,
    share: Vec<(VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>)>,
}

impl DecryptionShare {
    pub fn new(
        index: usize,
        share: Vec<(VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>)>,
    ) -> Self {
        Self { index, share }
    }
}

pub static LOOKUP_TABLE: LazyLock<DiscreteLogTable<Ristretto>> =
    LazyLock::new(|| DiscreteLogTable::<Ristretto>::new(0..256));

pub fn decrypt_shares(
    key_set: PublicKeySet<Ristretto>,
    enc: Vec<Ciphertext<Ristretto>>,
    shares: Vec<DecryptionShare>,
) -> Option<Vec<u64>> {
    assert!(!shares.is_empty());
    // Transpose vectors
    let rows = shares.len();
    let cols = shares[0].share.len();
    let transposed = (0..cols).map(|col| {
        (0..rows)
            .map(|row| (shares[row].index, shares[row].share[col]))
            .collect::<Vec<_>>()
    });

    transposed
        .zip(enc)
        .filter_map(|(shares, enc)| {
            let dec_iter = shares
                .into_iter()
                .map(|(i, (share, proof))| {
                    let share = CandidateDecryption::from_bytes(&share.to_bytes()).unwrap();
                    key_set.verify_share(share, enc, i, &proof).unwrap()
                })
                .enumerate();
            Some((key_set.params().combine_shares(dec_iter)?, enc))
        })
        .map(|(combined, enc)| combined.decrypt(enc, &LOOKUP_TABLE))
        .collect::<Option<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    use elastic_elgamal::sharing::{ActiveParticipant, Dealer, Params};

    #[test]
    fn test_decrypt_shares() -> anyhow::Result<()> {
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

                let share = p.decrypt_share(encrypted, &mut rng);
                DecryptionShare::new(i, vec![share])
            })
            .collect();

        let decrypted = decrypt_shares(key_set, vec![encrypted], shares).unwrap();
        assert_eq!(decrypted[0], plaintext);
        Ok(())
    }
}

use elastic_elgamal::{
    group::Ristretto, sharing::PublicKeySet, CandidateDecryption, DiscreteLogTable,
    LogEqualityProof, VerifiableDecryption,
};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

pub type Ciphertext = elastic_elgamal::Ciphertext<Ristretto>;

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
    enc: Vec<Ciphertext>,
    shares: Vec<DecryptionShare>,
) -> Option<Vec<u64>> {
    if shares.iter().any(|s| s.share.len() != enc.len()) {
        return None;
    }
    // Transpose vectors
    let rows = shares.len();
    let cols = enc.len();
    let transposed = (0..cols).map(|col| {
        (0..rows)
            .map(|row| (shares[row].index, shares[row].share[col]))
            .collect::<Vec<_>>()
    });

    transposed
        .zip(enc)
        .map(|(shares, enc)| {
            let dec_iter = shares
                .into_iter()
                .filter_map(|(i, (share, proof))| {
                    let share = CandidateDecryption::from_bytes(&share.to_bytes())?;
                    key_set.verify_share(share, enc, i, &proof).ok()
                })
                .enumerate();
            let combined = key_set.params().combine_shares(dec_iter)?;
            combined.decrypt(enc, &LOOKUP_TABLE)
        })
        .collect::<Option<Vec<_>>>()
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
    fn test_decrypt_shares() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);
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

    #[test]
    fn test_decrypt_empty() -> anyhow::Result<()> {
        let (key_set, ..) = setup(3, 2);

        let shares: Vec<_> = (0..2).map(|i| DecryptionShare::new(i, vec![])).collect();

        let decrypted = decrypt_shares(key_set, vec![], shares).unwrap();
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[test]
    fn test_decrypt_no_shares() -> anyhow::Result<()> {
        let (key_set, _dealer, mut rng) = setup(3, 2);

        let plaintext = 5u64;
        let encrypted = key_set.shared_key().encrypt(plaintext, &mut rng);

        let decrypted = decrypt_shares(key_set, vec![encrypted], vec![]);
        assert!(decrypted.is_none());
        Ok(())
    }

    #[test]
    fn test_decrypt_enough_shares() -> anyhow::Result<()> {
        let (key_set, dealer, mut rng) = setup(3, 2);

        let plaintext = 5u64;
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

        let decrypted = decrypt_shares(key_set, vec![encrypted], shares).unwrap();
        assert_eq!(decrypted[0], plaintext);
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

        let decrypted = decrypt_shares(key_set, vec![encrypted], shares);
        assert!(decrypted.is_none());
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

        let decrypted = decrypt_shares(key_set, vec![encrypted], shares);
        assert!(decrypted.is_none());
        Ok(())
    }
}

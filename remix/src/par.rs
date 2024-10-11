use elastic_elgamal::{group::Group, Ciphertext, PublicKey};
use rayon::prelude::*;

/// Same as [rerandomise](fn@super::rerandomise) but in parallel using [`rayon`].
pub fn rerandomise<G: Group>(
    x_cipher: &mut [Ciphertext<G>],
    y_cipher: &mut [Ciphertext<G>],
    enc_key: &PublicKey<G>,
) where
    G::Element: Send + Sync,
    G::Scalar: From<u32>,
{
    let x_iter = x_cipher.par_iter_mut();
    let y_iter = y_cipher.par_iter_mut();
    x_iter.zip(y_iter).for_each(|(x, y)| {
        let mut rng = rand::thread_rng();
        *x = super::ct_rerandomise(x, enc_key, &mut rng);
        *y = super::ct_rerandomise(y, enc_key, &mut rng);
    });
}

/// Same as [remix](fn@super::remix) but uses parallel [`rerandomise`].
pub fn remix<G: Group>(
    x_cipher: &mut [Ciphertext<G>],
    y_cipher: &mut [Ciphertext<G>],
    enc_key: &PublicKey<G>,
) where
    G::Element: Send + Sync,
    G::Scalar: From<u32>,
{
    assert_eq!(x_cipher.len(), y_cipher.len());
    let mut rng = rand::thread_rng();
    super::shuffle_pairs(x_cipher, y_cipher, &mut rng);
    super::shuffle_bits(x_cipher, y_cipher, &mut rng);
    rerandomise(x_cipher, y_cipher, enc_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ciphers_eq;
    use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Keypair};
    use rstest::rstest;

    #[rstest]
    fn test_par_rerandomise() {
        let mut rng = rand::thread_rng();
        let receiver = Keypair::<Ristretto>::generate(&mut rng);
        let enc_key = receiver.public();

        let message1: Vec<_> = (0..32).map(|i| (i % 2) as u32).collect();
        let message2 = message1.clone();

        let mut encrypt = |m: &u32| -> Ciphertext<Ristretto> { enc_key.encrypt(*m, &mut rng) };

        let mut ct1: Vec<_> = message1.iter().map(&mut encrypt).collect();
        let mut ct2: Vec<_> = message2.iter().map(&mut encrypt).collect();
        let prev_ct1 = ct1.clone();
        let prev_ct2 = ct2.clone();

        rerandomise(&mut ct1, &mut ct2, enc_key);

        // Not implementing `Eq` trait is criminal
        assert!(!ciphers_eq(&prev_ct1, &ct1));
        assert!(!ciphers_eq(&prev_ct2, &ct2));

        let lookup_table = DiscreteLogTable::new(0..2);
        let mut decrypt = |ct: &Ciphertext<Ristretto>| -> u32 {
            receiver.secret().decrypt(*ct, &lookup_table).unwrap() as u32
        };
        assert!(Iterator::eq(
            message1.into_iter(),
            ct1.iter().map(&mut decrypt)
        ));
        assert!(Iterator::eq(
            message2.into_iter(),
            ct2.iter().map(&mut decrypt)
        ));
    }
}

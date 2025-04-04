//! Implementation of the re-mixing described in the article :TBD:.

pub mod par;

use elastic_elgamal::{group::Group, Ciphertext, PublicKey};
use rand::{CryptoRng, Rng};

/// Shuffles groups of 2 [`Ciphertext`]s randomly but equally for both slices.
/// So, the ciphertext of the slices at given index before shuffling will endup randomly but at the same index after
/// the shuffle.
/// If the length of the slice it's not divisible by 2, meaning there's an incomplete pair, that lonely ciphertext is
/// not shuffled.
/// Internally, it uses the [Fisher-Yates shuffle].
///
/// [Fisher-Yates shuffle]: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
pub fn shuffle_pairs<T>(x_cipher: &mut [T], y_cipher: &mut [T], rng: &mut (impl Rng + CryptoRng)) {
    assert_eq!(x_cipher.len(), y_cipher.len());
    const STEP: usize = 2;
    let total_pairs = x_cipher.len() / STEP;
    for (pair_idx, arr_idx) in (0..x_cipher.len() - STEP).step_by(STEP).enumerate() {
        let swap_idx = rng.gen_range(pair_idx..total_pairs) * STEP;

        // TODO: make it more generic over STEP, this only works for pairs (STEP=2)
        x_cipher.swap(arr_idx, swap_idx);
        x_cipher.swap(arr_idx + 1, swap_idx + 1);
        y_cipher.swap(arr_idx, swap_idx);
        y_cipher.swap(arr_idx + 1, swap_idx + 1);
    }
}

/// Iterates over every pair of [`Ciphertext`] and flips a coin (probability of 50%) to swap the ciphertexts
/// on the pair.
pub fn shuffle_bits<T>(x_cipher: &mut [T], y_cipher: &mut [T], rng: &mut (impl Rng + CryptoRng)) {
    assert_eq!(x_cipher.len(), y_cipher.len());
    for i in (0..x_cipher.len()).step_by(2) {
        // Coin flip 50/50
        if rng.gen() {
            x_cipher.swap(i, i + 1);
            y_cipher.swap(i, i + 1);
        }
    }
}

/// Iterates over every [`Ciphertext`] and rerandomises with the same but random [`Scalar`].
pub fn rerandomise<G: Group>(
    x_cipher: &mut [Ciphertext<G>],
    y_cipher: &mut [Ciphertext<G>],
    enc_key: &PublicKey<G>,
    rng: &mut (impl Rng + CryptoRng),
) where
    G::Element: Send + Sync,
    G::Scalar: From<u32>,
{
    let x_iter = x_cipher.iter_mut();
    let y_iter = y_cipher.iter_mut();
    x_iter.zip(y_iter).for_each(|(x, y)| {
        *x = ct_rerandomise(x, enc_key, rng);
        *y = ct_rerandomise(y, enc_key, rng);
    });
}

/// Encapsulates all the procedures of re-mixing into one function.
/// It calls [`shuffle_pairs`], [`shuffle_bits`], [`rerandomise`] in this order.
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
    shuffle_pairs(x_cipher, y_cipher, &mut rng);
    shuffle_bits(x_cipher, y_cipher, &mut rng);
    rerandomise(x_cipher, y_cipher, enc_key, &mut rng);
}

fn ct_rerandomise<G: Group>(
    ciphertext: &Ciphertext<G>,
    public_key: &PublicKey<G>,
    rng: &mut (impl Rng + CryptoRng),
) -> Ciphertext<G>
where
    G::Scalar: From<u32>,
{
    *ciphertext + public_key.encrypt(0u32, rng)
}

#[allow(dead_code)]
fn ciphers_eq<G: Group>(ct1: &[Ciphertext<G>], ct2: &[Ciphertext<G>]) -> bool {
    std::iter::zip(ct1, ct2).all(|(x, y)| {
        // I think this is correct, don't quote me on that
        x.blinded_element() == y.blinded_element() && x.random_element() == y.random_element()
    })
}

#[cfg(test)]
mod tests {
    use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Keypair};
    use rand::{rngs::StdRng, SeedableRng};
    use rstest::{fixture, rstest};
    use std::slice;

    use super::*;

    const N_SIZE: usize = 32;

    #[fixture]
    fn rng() -> impl Rng + CryptoRng {
        StdRng::seed_from_u64(7)
    }

    #[fixture]
    fn key_pair() -> Keypair<Ristretto> {
        let mut rng = rng();
        Keypair::generate(&mut rng)
    }

    #[fixture]
    fn ct1() -> Vec<Ciphertext<Ristretto>> {
        let mut rng = rng();
        let key_pair = key_pair();
        let pub_key = key_pair.public();

        (0..N_SIZE)
            .map(|i| pub_key.encrypt((i % 2) as u64, &mut rng))
            .collect()
    }

    #[fixture]
    fn ct2() -> Vec<Ciphertext<Ristretto>> {
        ct1() // a clone for now
    }

    #[rstest]
    fn test_shuffle_pairs(
        mut ct1: Vec<Ciphertext<Ristretto>>,
        mut ct2: Vec<Ciphertext<Ristretto>>,
        mut rng: impl Rng + CryptoRng,
    ) {
        let prev_ct = ct1.clone();
        shuffle_pairs(&mut ct1, &mut ct2, &mut rng);

        assert!(ciphers_eq(&ct1, &ct2));
        assert!(!ciphers_eq(&prev_ct, &ct1));
    }

    #[rstest]
    fn test_shuffle_bits(
        mut ct1: Vec<Ciphertext<Ristretto>>,
        mut ct2: Vec<Ciphertext<Ristretto>>,
        mut rng: impl Rng + CryptoRng,
    ) {
        let prev_c = ct1.clone();

        shuffle_bits(&mut ct1, &mut ct2, &mut rng);

        assert!(ciphers_eq(&ct1, &ct2));
        assert!(!ciphers_eq(&prev_c, &ct1));
    }

    #[rstest]
    fn test_rerandomise(mut rng: impl Rng + CryptoRng, key_pair: Keypair<Ristretto>) {
        let message = 127u64;
        let mut ct1 = key_pair.public().encrypt(message, &mut rng);
        let mut ct2 = key_pair.public().encrypt(message, &mut rng);
        let prev_ct1 = ct1;
        let prev_ct2 = ct2;

        let ct1 = slice::from_mut(&mut ct1);
        let ct2 = slice::from_mut(&mut ct2);
        let prev_ct1 = slice::from_ref(&prev_ct1);
        let prev_ct2 = slice::from_ref(&prev_ct2);

        assert!(!ciphers_eq(ct1, ct2));

        rerandomise(ct1, ct2, key_pair.public(), &mut rng);

        assert!(!ciphers_eq(prev_ct1, ct1));
        assert!(!ciphers_eq(prev_ct2, ct2));
        let lookup_table = DiscreteLogTable::new(0..256);
        assert_eq!(
            message,
            key_pair.secret().decrypt(ct1[0], &lookup_table).unwrap()
        );
        assert_eq!(
            message,
            key_pair.secret().decrypt(ct2[0], &lookup_table).unwrap()
        );
    }

    #[rstest]
    fn test_ct_rerandomise() {
        let mut rng = rand::thread_rng();
        let receiver = Keypair::<Ristretto>::generate(&mut rng);
        let enc_key = receiver.public();

        let ct = enc_key.encrypt(10u32, &mut rng);
        let rand_ct = ct_rerandomise(&ct, enc_key, &mut rng);

        assert_ne!(ct.blinded_element(), rand_ct.blinded_element());
        assert_ne!(ct.random_element(), rand_ct.random_element());

        let lookup_table = DiscreteLogTable::new(0..20);
        let dec = receiver.secret().decrypt(ct, &lookup_table);
        let rand_dec = receiver.secret().decrypt(rand_ct, &lookup_table);

        assert_eq!(dec, rand_dec);
    }
}

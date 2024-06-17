use rand::{CryptoRng, Rng};
use rust_elgamal::{Ciphertext, DecryptionKey, Scalar};
use std::iter::zip;

fn shuffle_pairs(
    x_cipher: &mut [Ciphertext],
    y_cipher: &mut [Ciphertext],
    rng: &mut (impl Rng + CryptoRng),
) {
    // Fisher-Yates shuffle:
    // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
    const STEP: usize = 2;
    let total_pairs = x_cipher.len() / STEP;
    for (pair_idx, arr_idx) in (0..x_cipher.len() - STEP).step_by(STEP).enumerate() {
        let swap_idx = rng.gen_range(pair_idx..total_pairs) * STEP;

        x_cipher.swap(arr_idx, swap_idx);
        x_cipher.swap(arr_idx + 1, swap_idx + 1);
        y_cipher.swap(arr_idx, swap_idx);
        y_cipher.swap(arr_idx + 1, swap_idx + 1);
    }
}

fn shuffle_bits(
    x_cipher: &mut [Ciphertext],
    y_cipher: &mut [Ciphertext],
    rng: &mut (impl Rng + CryptoRng),
) {
    for i in (0..x_cipher.len()).step_by(2) {
        // Coin flip 50/50
        if rng.gen() {
            x_cipher.swap(i, i + 1);
            y_cipher.swap(i, i + 1);
        }
    }
}

pub fn rerandomise(
    x_cipher: &mut [Ciphertext],
    y_cipher: &mut [Ciphertext],
    rng: &mut (impl Rng + CryptoRng),
) {
    let dec_key = DecryptionKey::new(rng);
    let enc_key = dec_key.encryption_key();
    zip(x_cipher, y_cipher).for_each(|(x, y)| {
        let r = Scalar::from(rng.gen::<u32>());
        *x = enc_key.rerandomise_with(*x, r);
        *y = enc_key.rerandomise_with(*y, r);
    });
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};

    use super::*;

    const N_SIZE: usize = 8;

    #[test]
    fn shuffle_pairs_test() {
        let mut rng = StdRng::seed_from_u64(7);
        let dec_key = DecryptionKey::new(&mut rng);
        let enc_key = dec_key.encryption_key();

        let mut c1: Vec<_> = (0..N_SIZE)
            .map(|i| enc_key.encrypt(&Scalar::from((i % 2) as u8) * &GENERATOR_TABLE, &mut rng))
            .collect();
        let mut c2 = c1.clone();

        let prev_c = c1.clone();

        shuffle_pairs(&mut c1, &mut c2, &mut rng);

        assert_eq!(c1, c2);
        assert_ne!(prev_c, c1);
    }

    #[test]
    fn shuffle_bits_test() {
        let mut rng = StdRng::seed_from_u64(7);
        let dec_key = DecryptionKey::new(&mut rng);
        let enc_key = dec_key.encryption_key();

        let mut c1: Vec<_> = (0..N_SIZE)
            .map(|i| enc_key.encrypt(&Scalar::from((i % 2) as u8) * &GENERATOR_TABLE, &mut rng))
            .collect();
        let mut c2 = c1.clone();

        let prev_c = c1.clone();

        shuffle_bits(&mut c1, &mut c2, &mut rng);

        assert_eq!(c1, c2);
        assert_ne!(prev_c, c1);
    }

    #[test]
    fn rerandomise_test() {
        let mut rng = StdRng::seed_from_u64(7);
        let dec_key = DecryptionKey::new(&mut rng);
        let enc_key = dec_key.encryption_key();

        let message: Vec<_> = (0..N_SIZE)
            .map(|i| &Scalar::from((i % 2) as u8) * &GENERATOR_TABLE)
            .collect();

        let mut c1: Vec<_> = message
            .iter()
            .map(|m| enc_key.encrypt(*m, &mut rng))
            .collect();
        let mut c2 = c1.clone();

        rerandomise(&mut c1, &mut c2, &mut rng);
    }
}

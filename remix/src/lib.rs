use rand::{CryptoRng, Rng};
use rust_elgamal::{Ciphertext, EncryptionKey, Scalar};
use std::iter::zip;

pub mod par;

pub fn shuffle_pairs(
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

pub fn shuffle_bits(
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
    enc_key: &EncryptionKey,
    rng: &mut (impl Rng + CryptoRng),
) {
    zip(x_cipher, y_cipher).for_each(|(x, y)| {
        let r = Scalar::from(rng.gen::<u32>());
        enc_key.rerandomise_with(*x, r);
        enc_key.rerandomise_with(*y, r);
    });
}

pub fn remix(x_cipher: &mut [Ciphertext], y_cipher: &mut [Ciphertext], enc_key: &EncryptionKey) {
    let mut rng = rand::thread_rng();
    shuffle_pairs(x_cipher, y_cipher, &mut rng);
    shuffle_bits(x_cipher, y_cipher, &mut rng);
    rerandomise(x_cipher, y_cipher, enc_key, &mut rng);
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use rstest::{fixture, rstest};
    use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
    use std::slice;

    use super::*;

    const N_SIZE: usize = 32;

    #[fixture]
    fn rng() -> impl Rng + CryptoRng {
        StdRng::seed_from_u64(7)
    }

    #[fixture]
    fn dec_key() -> DecryptionKey {
        let mut rng = rng();
        DecryptionKey::new(&mut rng)
    }

    #[fixture]
    fn ct1() -> Vec<Ciphertext> {
        let mut rng = rng();
        let dec_key = dec_key();
        let enc_key = dec_key.encryption_key();

        (0..N_SIZE)
            .map(|i| enc_key.encrypt(&Scalar::from((i % 2) as u8) * &GENERATOR_TABLE, &mut rng))
            .collect()
    }

    #[fixture]
    fn ct2() -> Vec<Ciphertext> {
        ct1() // a clone for now
    }

    #[rstest]
    fn test_shuffle_pairs(
        mut ct1: Vec<Ciphertext>,
        mut ct2: Vec<Ciphertext>,
        mut rng: impl Rng + CryptoRng,
    ) {
        let prev_ct = ct1.clone();

        shuffle_pairs(&mut ct1, &mut ct2, &mut rng);

        assert_eq!(ct1, ct2);
        assert_ne!(prev_ct, ct1);
    }

    #[rstest]
    fn test_shuffle_bits(
        mut ct1: Vec<Ciphertext>,
        mut ct2: Vec<Ciphertext>,
        mut rng: impl Rng + CryptoRng,
    ) {
        let prev_c = ct1.clone();

        shuffle_bits(&mut ct1, &mut ct2, &mut rng);

        assert_eq!(ct1, ct2);
        assert_ne!(prev_c, ct1);
    }

    #[rstest]
    fn test_rerandomise(mut rng: impl Rng + CryptoRng, dec_key: DecryptionKey) {
        let message = &Scalar::from(123456789u32) * &GENERATOR_TABLE;
        let mut ct1 = dec_key.encryption_key().encrypt(message, &mut rng);
        let mut ct2 = dec_key.encryption_key().encrypt(message, &mut rng);
        assert_ne!(ct1, ct2);

        rerandomise(
            slice::from_mut(&mut ct1),
            slice::from_mut(&mut ct2),
            dec_key.encryption_key(),
            &mut rng,
        );

        assert_eq!(message, dec_key.decrypt(ct1));
        assert_eq!(message, dec_key.decrypt(ct2));
    }
}

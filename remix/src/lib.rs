#![feature(test)]
extern crate test;

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

fn rerandomise(
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

pub fn remix(x_cipher: &mut [Ciphertext], y_cipher: &mut [Ciphertext]) {
    let mut rng = rand::thread_rng();
    shuffle_pairs(x_cipher, y_cipher, &mut rng);
    shuffle_bits(x_cipher, y_cipher, &mut rng);
    rerandomise(x_cipher, y_cipher, &mut rng);
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
    use test::Bencher;

    use super::*;

    const N_SIZE: usize = 32;

    fn setup() -> ((impl Rng + CryptoRng), DecryptionKey) {
        let mut rng = StdRng::seed_from_u64(7);
        let dec_key = DecryptionKey::new(&mut rng);

        (rng, dec_key)
    }

    #[test]
    fn test_shuffle_pairs() {
        let (mut rng, dec_key) = setup();
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
    fn test_shuffle_bits() {
        let (mut rng, dec_key) = setup();
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
    fn test_rerandomise() {
        let (mut rng, dec_key) = setup();
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

    fn setup_bench(num_bits: usize) -> (Vec<Ciphertext>, Vec<Ciphertext>, (impl Rng + CryptoRng)) {
        let (mut rng, dec_key) = setup();
        let enc_key = dec_key.encryption_key();

        let ct1: Vec<_> = (0..num_bits)
            .map(|i| enc_key.encrypt(&Scalar::from((i % 2) as u8) * &GENERATOR_TABLE, &mut rng))
            .collect();
        let ct2 = ct1.clone();

        (ct1, ct2, rng)
    }

    #[bench]
    fn bench_shuffle_pairs(b: &mut Bencher) {
        let (mut ct1, mut ct2, mut rng) = setup_bench(N_SIZE);

        b.iter(|| {
            shuffle_pairs(&mut ct1, &mut ct2, &mut rng);
        });
    }

    #[bench]
    fn bench_shuffle_bits(b: &mut Bencher) {
        let (mut ct1, mut ct2, mut rng) = setup_bench(N_SIZE);

        b.iter(|| {
            shuffle_bits(&mut ct1, &mut ct2, &mut rng);
        });
    }

    #[bench]
    fn bench_rerandomize(b: &mut Bencher) {
        let (mut ct1, mut ct2, mut rng) = setup_bench(N_SIZE);

        b.iter(|| {
            rerandomise(&mut ct1, &mut ct2, &mut rng);
        });
    }
}

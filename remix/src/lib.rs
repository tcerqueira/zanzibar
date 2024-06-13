use rand::Rng;

pub mod cipher;

pub use cipher::Cipher;

/// Shuffles bit pairs randomly in the same way on both ciphers.
fn shuffle_pairs<const N: usize>(
    x_cipher: &mut Cipher<N>,
    y_cipher: &mut Cipher<N>,
    rng: &mut impl Rng,
) {
    let total_pairs = x_cipher.len() * 4;
    // Fisher-Yates shuffle:
    // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
    for i in (1..total_pairs).rev() {
        let j = rng.gen_range(0..=i);

        x_cipher.swap_pair(i, j);
        y_cipher.swap_pair(i, j);
    }
}

/// Shuffles bits on the pairs randomly in the same way on both ciphers.
fn shuffle_bits<const N: usize>(
    x_cipher: &mut Cipher<N>,
    y_cipher: &mut Cipher<N>,
    rng: &mut impl Rng,
) {
    let total_pairs = x_cipher.len() * 4;
    for idx in 0..total_pairs {
        // Coin flip 50/50
        if rng.gen() {
            x_cipher.swap_bits_on_pair(idx);
            y_cipher.swap_bits_on_pair(idx);
        }
    }
}

/// Rerandomize algorithm. Takes 2 ciphers and shuffles the bit pairs and the bits on the pairs in the same way on both
/// ciphers.
pub fn rerandomize<const N: usize>(x_cipher: &mut Cipher<N>, y_cipher: &mut Cipher<N>) {
    let mut rng = rand::thread_rng();
    shuffle_pairs(x_cipher, y_cipher, &mut rng);
    shuffle_bits(x_cipher, y_cipher, &mut rng);
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn shuffle_pairs_test() {
        let mut c1 = Cipher::new([0b00000000, 0b11111111]);
        let mut c2 = Cipher::new([0b11111111, 0b00000000]);
        // The value 7 as a seed makes the bytes swap places
        let mut rng = StdRng::seed_from_u64(7);

        shuffle_pairs(&mut c1, &mut c2, &mut rng);

        assert_eq!(c1, Cipher::new([0b11111111, 0b00000000]));
        assert_eq!(c2, Cipher::new([0b00000000, 0b11111111]));
    }

    #[test]
    fn shuffle_bits_test() {
        let mut c1 = Cipher::new([0b10101010, 0b10101010]);
        let mut c2 = Cipher::new([0b01010101, 0b01010101]);
        let mut rng = StdRng::seed_from_u64(2);

        shuffle_bits(&mut c1, &mut c2, &mut rng);

        assert_eq!(c1, Cipher::new([0b10011010, 0b10011010]));
        assert_eq!(c2, Cipher::new([0b01100101, 0b01100101]));
    }

    #[test]
    fn rerandomize_test() {
        let mut c1 = Cipher::new([0b00000000, 0b11111111]);
        let mut c2 = Cipher::new([0b00000000, 0b11111111]);

        rerandomize(&mut c1, &mut c2);

        assert_eq!(c1, c2);
    }
}

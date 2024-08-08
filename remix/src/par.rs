use rand::Rng;
use rayon::prelude::*;
use rust_elgamal::{Ciphertext, EncryptionKey, Scalar};

/// Same as [rerandomise](fn@super::rerandomise) but in parallel using [`rayon`].
pub fn rerandomise(
    x_cipher: &mut [Ciphertext],
    y_cipher: &mut [Ciphertext],
    enc_key: &EncryptionKey,
) {
    let x_iter = x_cipher.par_iter_mut();
    let y_iter = y_cipher.par_iter_mut();
    x_iter.zip(y_iter).for_each(|(x, y)| {
        let mut rng = rand::thread_rng();
        let r = Scalar::from(rng.gen::<u32>());
        *x = enc_key.rerandomise_with(*x, r);
        let r = Scalar::from(rng.gen::<u32>());
        *y = enc_key.rerandomise_with(*y, r);
    });
}

/// Same as [remix](fn@super::remix) but uses parallel [`rerandomise`].
pub fn remix(x_cipher: &mut [Ciphertext], y_cipher: &mut [Ciphertext], enc_key: &EncryptionKey) {
    assert_eq!(x_cipher.len(), y_cipher.len());
    let mut rng = rand::thread_rng();
    super::shuffle_pairs(x_cipher, y_cipher, &mut rng);
    super::shuffle_bits(x_cipher, y_cipher, &mut rng);
    rerandomise(x_cipher, y_cipher, enc_key);
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rust_elgamal::{DecryptionKey, RistrettoPoint, GENERATOR_TABLE};

    use super::*;

    const N_SIZE: usize = 32;

    #[rstest]
    fn test_par_rerandomise() {
        let mut rng = rand::thread_rng();
        let dec_key = DecryptionKey::new(&mut rng);
        let enc_key = dec_key.encryption_key();

        let message1: Vec<_> = (0..N_SIZE)
            .map(|i| &Scalar::from((i % 2) as u8) * &GENERATOR_TABLE)
            .collect();
        let message2 = message1.clone();

        let mut encrypt = |m: &RistrettoPoint| -> Ciphertext { enc_key.encrypt(*m, &mut rng) };

        let mut ct1: Vec<_> = message1.iter().map(&mut encrypt).collect();
        let mut ct2: Vec<_> = message2.iter().map(&mut encrypt).collect();
        let prev_ct1 = ct1.clone();
        let prev_ct2 = ct2.clone();

        rerandomise(&mut ct1, &mut ct2, dec_key.encryption_key());

        assert_ne!(prev_ct1, ct1);
        assert_ne!(prev_ct2, ct2);

        let mut decrypt = |ct: &Ciphertext| -> RistrettoPoint { dec_key.decrypt(*ct) };
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

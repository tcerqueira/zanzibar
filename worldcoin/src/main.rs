use rand::Rng;

const N_SIZE: usize = 3225;

fn main() {
    let mut rng = rand::thread_rng();
    let _new_user: [u8; N_SIZE] = rng.gen();
    let _archived_user: [u8; N_SIZE] = rng.gen();

    // Encrypt

    // Shuffle + Rerandomize

    // Decrypt

    // Assert result
}

#[cfg(test)]
mod tests {

    #[test]
    fn rand_rerandomize() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};

        // const N: usize = 100;

        let mut rng = StdRng::from_entropy();
        let dec_key = DecryptionKey::new(&mut rng);
        let enc_key = dec_key.encryption_key();

        let message = &Scalar::from(5u32) * &GENERATOR_TABLE;
        let mut encrypted = enc_key.encrypt(message, &mut rng);
        // added
        {
            encrypted = enc_key.rerandomise(encrypted, &mut rng);
        }
        // ---
        let decrypted = dec_key.decrypt(encrypted);
        assert_eq!(message, decrypted);
    }
}

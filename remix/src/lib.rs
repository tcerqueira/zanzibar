use rand::Rng;

#[derive(Debug)]
pub struct Cipher<const N: usize>([u8; N]);

#[derive(Debug, Clone, Copy)]
struct BitPairIndices {
    byte_idx: usize,
    bit_idx: usize,
}

impl<const N: usize> Cipher<N> {
    pub fn new(bits: [u8; N]) -> Self {
        Self(bits)
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    pub fn bit_pair(&self, idx: usize) -> u8 {
        let indices = self.bit_pair_indices(idx);
        self.bit_pair_from_indices(indices)
    }

    pub fn set_bit_pair(&mut self, idx: usize, value: u8) {
        let indices = self.bit_pair_indices(idx);
        self.set_bit_pair_from_indices(indices, value);
    }

    pub fn swap_pair(&mut self, x_idx: usize, y_idx: usize) {
        let x_indices = self.bit_pair_indices(x_idx);
        let y_indices = self.bit_pair_indices(y_idx);

        let x_pair = self.bit_pair_from_indices(x_indices);
        let y_pair = self.bit_pair_from_indices(y_indices);

        self.set_bit_pair_from_indices(x_indices, y_pair);
        self.set_bit_pair_from_indices(y_indices, x_pair);
    }

    fn bit_pair_indices(&self, idx: usize) -> BitPairIndices {
        BitPairIndices {
            byte_idx: idx / 4,
            bit_idx: (idx % 4) * 2,
        }
    }

    fn bit_pair_from_indices(&self, indices: BitPairIndices) -> u8 {
        let BitPairIndices { byte_idx, bit_idx } = indices;
        (self.0[byte_idx] >> (6 - bit_idx)) & 0b11
    }

    fn set_bit_pair_from_indices(&mut self, indices: BitPairIndices, value: u8) {
        let BitPairIndices { byte_idx, bit_idx } = indices;

        let mask = !(0b11 << (6 - bit_idx));
        let cleared_byte = self.0[byte_idx] & mask;
        self.0[byte_idx] = cleared_byte | ((value & 0b11) << (6 - bit_idx));
    }
}

pub fn rerandomize<const N: usize>(
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

impl<const N: usize> AsRef<[u8; N]> for Cipher<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8; N]> for &mut Cipher<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn it_works() {
        let mut c1 = Cipher::new([0b00000000, 0b11111111]);
        let mut c2 = Cipher::new([0b11111111, 0b00000000]);
        // The value 7 as a seed makes the bytes swap places
        let mut rng = StdRng::seed_from_u64(7);

        rerandomize(&mut c1, &mut c2, &mut rng);

        assert_eq!(c1.as_ref(), &[0b11111111, 0b00000000]);
        assert_eq!(c2.as_ref(), &[0b00000000, 0b11111111]);
    }

    #[test]
    fn bit_pair() {
        let cipher = Cipher::new([0b00011011, 0b11100100]);

        assert_eq!(cipher.bit_pair(0), 0b00);
        assert_eq!(cipher.bit_pair(2), 0b10);
        assert_eq!(cipher.bit_pair(4), 0b11);
        assert_eq!(cipher.bit_pair(6), 0b01);
    }

    #[test]
    fn set_bit_pair() {
        let mut cipher = Cipher::new([0b00011011, 0b11100100]);

        cipher.set_bit_pair(0, 0b11);
        assert_eq!(cipher.as_ref(), &[0b11011011, 0b11100100]);
        cipher.set_bit_pair(2, 0b01);
        assert_eq!(cipher.as_ref(), &[0b11010111, 0b11100100]);
        cipher.set_bit_pair(4, 0b00);
        assert_eq!(cipher.as_ref(), &[0b11010111, 0b00100100]);
        cipher.set_bit_pair(6, 0b10);
        assert_eq!(cipher.as_ref(), &[0b11010111, 0b00101000]);

        assert_eq!(cipher.bit_pair(0), 0b11);
        assert_eq!(cipher.bit_pair(2), 0b01);
        assert_eq!(cipher.bit_pair(4), 0b00);
        assert_eq!(cipher.bit_pair(6), 0b10);
    }
}

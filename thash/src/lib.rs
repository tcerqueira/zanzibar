#![allow(dead_code)]
use bitvec::prelude::*;
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use noisy_float::types::n64;

// Function to convert BitVec to Array1<f32>
fn bitvec_to_array(bv: &BitVec) -> Array1<i32> {
    bv.iter().map(|b| if *b { 1 } else { 0 }).collect()
}

// Perceptual hash function
fn threshold_hash(bv: &BitVec, threshold: usize) -> BitVec {
    let arr = bitvec_to_array(bv);
    let reshaped = arr.into_shape((threshold, bv.len() / threshold)).unwrap();

    // Compute the mean of each row
    let row_means: Array1<i32> = reshaped.mean_axis(ndarray::Axis(1)).unwrap();
    let mut row_means_mean = row_means.clone();

    // Compute the median of the means
    let median = row_means_mean
        .quantile_axis_mut(
            ndarray::Axis(0),
            n64(0.5),
            &ndarray_stats::interpolate::Linear,
        )
        .unwrap()
        .into_scalar();

    // Create the hash
    row_means.iter().map(|&x| x > median).collect()
}

// Hamming distance between two BitVecs
fn hamming_distance(bv1: BitVec, bv2: BitVec) -> usize {
    (bv1 ^ bv2).count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thash() {
        let threshold = 4;
        // Example usage
        let bv1 = bitvec![1, 0, 1, 0, 1, 1, 0, 0];
        let bv2 = bitvec![1, 1, 0, 0, 1, 0, 1, 0];

        let hash1 = threshold_hash(&bv1, threshold);
        let hash2 = threshold_hash(&bv2, threshold);

        println!("Hash 1: {:?}", hash1);
        println!("Hash 2: {:?}", hash2);
        println!("Hamming distance: {}", hamming_distance(hash1, hash2));
        println!("Hamming distance bitvecs: {}", hamming_distance(bv1, bv2));
    }
}

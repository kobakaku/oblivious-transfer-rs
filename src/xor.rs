//! XOR operations module - blackboxed for security

use anyhow::Result;

/// Performs bitwise XOR on two byte arrays
/// This function is intentionally separated to act as a blackbox operation
pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    // Ensure both arrays have the same length by padding with zeros
    let max_len = std::cmp::max(a.len(), b.len());
    let mut a_padded = a.to_vec();
    let mut b_padded = b.to_vec();
    a_padded.resize(max_len, 0);
    b_padded.resize(max_len, 0);

    // Perform bitwise XOR operation
    Ok(a_padded
        .iter()
        .zip(b_padded.iter())
        .map(|(x, y)| x ^ y)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_equal_length() -> Result<()> {
        let a = vec![0x12, 0x34, 0x56];
        let b = vec![0xAB, 0xCD, 0xEF];
        let expected = vec![0x12 ^ 0xAB, 0x34 ^ 0xCD, 0x56 ^ 0xEF];

        let result = xor(&a, &b)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_xor_different_lengths() -> Result<()> {
        let a = vec![0x12, 0x34];
        let b = vec![0xAB, 0xCD, 0xEF];
        let expected = vec![0x12 ^ 0xAB, 0x34 ^ 0xCD, 0x00 ^ 0xEF];

        let result = xor(&a, &b)?;
        assert_eq!(result, expected);
        Ok(())
    }
}

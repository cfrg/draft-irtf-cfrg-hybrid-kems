//! Utility functions for byte string operations
//!
//! This module provides concat and split functions as specified in
//! draft-irtf-cfrg-hybrid-kems, plus const utility functions and common hybrid types.

use crate::error::KemError;
use crate::traits::AsBytes;

/// Const function to compute the minimum of two values
pub const fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

/// Const function to compute the maximum of two values  
pub const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// Concatenation of byte strings
///
/// Takes a slice of byte slices and concatenates them into a single Vec<u8>.
/// concat([0x01, 0x0203, 0x040506]) = 0x010203040506
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total_len = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);

    for slice in slices {
        result.extend_from_slice(slice);
    }

    result
}

/// Split a byte string into two parts
///
/// Split a byte string `x` of length `N1 + N2` into its first `N1` bytes
/// and its last `N2` bytes. This function is the inverse of concat(x1, x2)
/// when x1 is N1 bytes long and x2 is N2 bytes long.
///
/// Returns an error if the input doesn't have length N1 + N2.
/// This function operates in constant-time for given N1 and N2.
pub fn split(n1: usize, n2: usize, x: &[u8]) -> Result<(&[u8], &[u8]), KemError> {
    if x.len() != n1 + n2 {
        return Err(KemError::InvalidInputLength);
    }

    Ok((&x[..n1], &x[n1..]))
}

/// Consolidated hybrid value type for keys and ciphertexts
pub struct HybridValue(pub Vec<u8>);

impl HybridValue {
    /// Create a new hybrid value from two values that implement AsBytes
    pub fn new(first: &impl AsBytes, second: &impl AsBytes) -> Self {
        let bytes = concat(&[first.as_bytes(), second.as_bytes()]);
        HybridValue(bytes)
    }

    /// Split the hybrid value into two parts of specified lengths
    pub fn split(&self, first_len: usize, second_len: usize) -> Result<(&[u8], &[u8]), KemError> {
        if self.0.len() != first_len + second_len {
            return Err(KemError::InvalidInputLength);
        }
        Ok((&self.0[..first_len], &self.0[first_len..]))
    }
}

impl AsBytes for HybridValue {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for HybridValue {
    fn from(bytes: &'a [u8]) -> Self {
        HybridValue(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concat_basic() {
        let result = concat(&[&[0x01], &[0x02, 0x03], &[0x04, 0x05, 0x06]]);
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_concat_empty() {
        let result = concat(&[]);
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_concat_single() {
        let result = concat(&[&[0x01, 0x02, 0x03]]);
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_split_basic() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let (first, second) = split(2, 4, &data).unwrap();
        assert_eq!(first, &[0x01, 0x02]);
        assert_eq!(second, &[0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_split_error() {
        let data = [0x01, 0x02, 0x03];
        let result = split(2, 2, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_concat_split_roundtrip() {
        let x1 = &[0x01, 0x02];
        let x2 = &[0x03, 0x04, 0x05];

        let concatenated = concat(&[x1, x2]);
        let (split1, split2) = split(x1.len(), x2.len(), &concatenated).unwrap();

        assert_eq!(split1, x1);
        assert_eq!(split2, x2);
    }

    #[test]
    fn test_const_min() {
        assert_eq!(min(5, 10), 5);
        assert_eq!(min(10, 5), 5);
        assert_eq!(min(7, 7), 7);
    }

    #[test]
    fn test_const_max() {
        assert_eq!(max(5, 10), 10);
        assert_eq!(max(10, 5), 10);
        assert_eq!(max(7, 7), 7);
    }
}

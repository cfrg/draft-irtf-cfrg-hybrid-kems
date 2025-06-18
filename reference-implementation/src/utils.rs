//! Utility functions for byte string operations
//!
//! This module provides concat and split functions as specified in
//! draft-irtf-cfrg-hybrid-kems, plus const utility functions and common hybrid types.

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
pub fn split(n1: usize, n2: usize, x: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if x.len() != n1 + n2 {
        return Err("Input length does not match N1 + N2");
    }

    Ok((&x[..n1], &x[n1..]))
}

/// Hybrid encapsulation key as concatenated byte string
pub struct HybridEncapsulationKey(pub Vec<u8>);

impl AsBytes for HybridEncapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl HybridEncapsulationKey {
    /// Create a new hybrid encapsulation key from two byte slices
    pub fn new(first: &[u8], second: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(first.len() + second.len());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        HybridEncapsulationKey(bytes)
    }

    /// Split the hybrid key into two parts of specified lengths
    pub fn split(
        &self,
        first_len: usize,
        second_len: usize,
    ) -> Result<(&[u8], &[u8]), &'static str> {
        if self.0.len() != first_len + second_len {
            return Err("Total length does not match first_len + second_len");
        }
        Ok((&self.0[..first_len], &self.0[first_len..]))
    }
}

impl From<Vec<u8>> for HybridEncapsulationKey {
    fn from(bytes: Vec<u8>) -> Self {
        HybridEncapsulationKey(bytes)
    }
}

impl<'a> From<&'a [u8]> for HybridEncapsulationKey {
    fn from(bytes: &'a [u8]) -> Self {
        HybridEncapsulationKey(bytes.to_vec())
    }
}

/// Hybrid decapsulation key as concatenated byte string
pub struct HybridDecapsulationKey(pub Vec<u8>);

impl AsBytes for HybridDecapsulationKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl HybridDecapsulationKey {
    /// Create a new hybrid decapsulation key from two byte slices
    pub fn new(first: &[u8], second: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(first.len() + second.len());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        HybridDecapsulationKey(bytes)
    }

    /// Split the hybrid key into two parts of specified lengths
    pub fn split(
        &self,
        first_len: usize,
        second_len: usize,
    ) -> Result<(&[u8], &[u8]), &'static str> {
        if self.0.len() != first_len + second_len {
            return Err("Total length does not match first_len + second_len");
        }
        Ok((&self.0[..first_len], &self.0[first_len..]))
    }
}

impl From<Vec<u8>> for HybridDecapsulationKey {
    fn from(bytes: Vec<u8>) -> Self {
        HybridDecapsulationKey(bytes)
    }
}

impl<'a> From<&'a [u8]> for HybridDecapsulationKey {
    fn from(bytes: &'a [u8]) -> Self {
        HybridDecapsulationKey(bytes.to_vec())
    }
}

/// Hybrid ciphertext as concatenated byte string
pub struct HybridCiphertext(pub Vec<u8>);

impl AsBytes for HybridCiphertext {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl HybridCiphertext {
    /// Create a new hybrid ciphertext from two byte slices
    pub fn new(first: &[u8], second: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(first.len() + second.len());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        HybridCiphertext(bytes)
    }

    /// Split the hybrid ciphertext into two parts of specified lengths
    pub fn split(
        &self,
        first_len: usize,
        second_len: usize,
    ) -> Result<(&[u8], &[u8]), &'static str> {
        if self.0.len() != first_len + second_len {
            return Err("Total length does not match first_len + second_len");
        }
        Ok((&self.0[..first_len], &self.0[first_len..]))
    }
}

impl From<Vec<u8>> for HybridCiphertext {
    fn from(bytes: Vec<u8>) -> Self {
        HybridCiphertext(bytes)
    }
}

impl<'a> From<&'a [u8]> for HybridCiphertext {
    fn from(bytes: &'a [u8]) -> Self {
        HybridCiphertext(bytes.to_vec())
    }
}

/// Hybrid shared secret as byte string
pub struct HybridSharedSecret(pub Vec<u8>);

impl AsBytes for HybridSharedSecret {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl HybridSharedSecret {
    /// Create a new hybrid shared secret from two byte slices
    pub fn new(first: &[u8], second: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(first.len() + second.len());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        HybridSharedSecret(bytes)
    }

    /// Split the hybrid shared secret into two parts of specified lengths
    pub fn split(
        &self,
        first_len: usize,
        second_len: usize,
    ) -> Result<(&[u8], &[u8]), &'static str> {
        if self.0.len() != first_len + second_len {
            return Err("Total length does not match first_len + second_len");
        }
        Ok((&self.0[..first_len], &self.0[first_len..]))
    }
}

impl From<Vec<u8>> for HybridSharedSecret {
    fn from(bytes: Vec<u8>) -> Self {
        HybridSharedSecret(bytes)
    }
}

impl<'a> From<&'a [u8]> for HybridSharedSecret {
    fn from(bytes: &'a [u8]) -> Self {
        HybridSharedSecret(bytes.to_vec())
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

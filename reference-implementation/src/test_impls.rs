//! Test implementations of traits for testing and demonstration purposes
//!
//! These implementations fulfill the trait APIs in the simplest way possible
//! without being completely trivial. They are suitable for testing hybrid
//! KEM constructions but should not be used in production.

use crate::traits::{Kem, Kdf, Prg, NominalGroup};
use rand::CryptoRng;

/// Simple KDF that repeats input and XORs with a fixed pattern
pub struct TestKdf;

impl Kdf for TestKdf {
    const INPUT_LENGTH: usize = 32;
    const OUTPUT_LENGTH: usize = 32;
    
    type Error = ();
    
    fn kdf(input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut output = Vec::with_capacity(Self::OUTPUT_LENGTH);
        let xor_pattern = 0x5A; // Fixed XOR pattern
        
        // Repeat input to fill output length and XOR with pattern
        for i in 0..Self::OUTPUT_LENGTH {
            let input_byte = if input.is_empty() { 0 } else { input[i % input.len()] };
            output.push(input_byte ^ xor_pattern);
        }
        
        Ok(output)
    }
}

/// Simple PRG that uses a linear congruential generator seeded from input
pub struct TestPrg;

impl Prg for TestPrg {
    const INPUT_LENGTH: usize = 16;
    const OUTPUT_LENGTH: usize = 64;
    
    type Error = ();
    
    fn prg(seed: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Convert seed to u64 for LCG
        let mut state = 0u64;
        for (i, &byte) in seed.iter().enumerate().take(8) {
            state |= (byte as u64) << (i * 8);
        }
        if state == 0 { state = 1; } // Ensure non-zero state
        
        let mut output = Vec::with_capacity(Self::OUTPUT_LENGTH);
        
        // Simple LCG: state = (a * state + c) mod 2^64
        let a = 1103515245u64;
        let c = 12345u64;
        
        for _ in 0..Self::OUTPUT_LENGTH {
            state = state.wrapping_mul(a).wrapping_add(c);
            output.push((state >> 8) as u8);
        }
        
        Ok(output)
    }
}

/// Simple test KEM using basic arithmetic operations
pub struct TestKem;

pub struct TestEncapsulationKey {
    pub bytes: [u8; 32],
}

impl AsRef<[u8]> for TestEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for TestEncapsulationKey {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(TestEncapsulationKey { bytes: key_bytes })
    }
}

pub struct TestDecapsulationKey {
    pub bytes: [u8; 16],
}

impl AsRef<[u8]> for TestDecapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for TestDecapsulationKey {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 16 {
            return Err(());
        }
        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(bytes);
        Ok(TestDecapsulationKey { bytes: key_bytes })
    }
}

pub struct TestCiphertext {
    pub bytes: [u8; 48],
}

impl AsRef<[u8]> for TestCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for TestCiphertext {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 48 {
            return Err(());
        }
        let mut ct_bytes = [0u8; 48];
        ct_bytes.copy_from_slice(bytes);
        Ok(TestCiphertext { bytes: ct_bytes })
    }
}

pub struct TestSharedSecret {
    pub bytes: [u8; 32],
}

impl AsRef<[u8]> for TestSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for TestSharedSecret {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(TestSharedSecret { bytes: array })
    }
}

impl Kem for TestKem {
    const SEED_LENGTH: usize = 16;
    const ENCAPSULATION_KEY_LENGTH: usize = 32;
    const DECAPSULATION_KEY_LENGTH: usize = 16;
    const CIPHERTEXT_LENGTH: usize = 48;
    const SHARED_SECRET_LENGTH: usize = 32;
    
    type EncapsulationKey = TestEncapsulationKey;
    type DecapsulationKey = TestDecapsulationKey;
    type Ciphertext = TestCiphertext;
    type SharedSecret = TestSharedSecret;
    type Error = ();
    
    fn generate_key_pair<R: CryptoRng>(rng: &mut R) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        let mut seed = [0u8; Self::SEED_LENGTH];
        rng.fill_bytes(&mut seed);
        Self::derive_key_pair(&seed)
    }
    
    fn derive_key_pair(seed: &[u8]) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(());
        }
        
        // Simple key derivation: stretch seed for private key, derive public key
        let mut dk_bytes = [0u8; 16];
        for i in 0..16 {
            dk_bytes[i] = seed[i % seed.len()].wrapping_add(i as u8);
        }
        
        // Public key = private key repeated and transformed
        let mut ek_bytes = [0u8; 32];
        for i in 0..32 {
            ek_bytes[i] = dk_bytes[i % 16].wrapping_mul(3).wrapping_add(7);
        }
        
        Ok((
            TestEncapsulationKey { bytes: ek_bytes },
            TestDecapsulationKey { bytes: dk_bytes }
        ))
    }
    
    fn encaps<R: CryptoRng>(ek: &Self::EncapsulationKey, rng: &mut R) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        Self::encaps_derand(ek, &randomness)
    }
    
    fn encaps_derand(ek: &Self::EncapsulationKey, randomness: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error> {
        // Simple encapsulation: combine public key with randomness
        let mut ct_bytes = [0u8; 48];
        let mut shared_secret = [0u8; 32];
        
        // First 32 bytes of ciphertext = randomness XOR public key
        for i in 0..32 {
            let rand_byte = if i < randomness.len() { randomness[i] } else { 0 };
            ct_bytes[i] = rand_byte ^ ek.bytes[i];
        }
        
        // Last 16 bytes of ciphertext = public key subset transformed
        for i in 0..16 {
            ct_bytes[32 + i] = ek.bytes[i].wrapping_add(randomness.get(i).copied().unwrap_or(0));
        }
        
        // Shared secret = hash-like function of public key and randomness
        for i in 0..32 {
            let pk_byte = ek.bytes[i % 32];
            let rand_byte = randomness.get(i % randomness.len()).copied().unwrap_or(0);
            shared_secret[i] = pk_byte.wrapping_add(rand_byte).wrapping_mul(5) ^ 0xAA;
        }
        
        Ok((TestCiphertext { bytes: ct_bytes }, TestSharedSecret { bytes: shared_secret }))
    }
    
    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, Self::Error> {
        // Reconstruct public key from private key
        let ek = Self::to_encapsulation_key(dk)?;
        
        // Extract randomness from ciphertext
        let mut randomness = [0u8; 32];
        for i in 0..32 {
            randomness[i] = ct.bytes[i] ^ ek.bytes[i];
        }
        
        // Recompute shared secret
        let mut shared_secret = [0u8; 32];
        for i in 0..32 {
            let pk_byte = ek.bytes[i % 32];
            let rand_byte = randomness[i % 32];
            shared_secret[i] = pk_byte.wrapping_add(rand_byte).wrapping_mul(5) ^ 0xAA;
        }
        
        Ok(TestSharedSecret { bytes: shared_secret })
    }
    
    
    fn to_encapsulation_key(dk: &Self::DecapsulationKey) -> Result<Self::EncapsulationKey, Self::Error> {
        // Reconstruct public key from private key
        let mut ek_bytes = [0u8; 32];
        for i in 0..32 {
            ek_bytes[i] = dk.bytes[i % 16].wrapping_mul(3).wrapping_add(7);
        }
        Ok(TestEncapsulationKey { bytes: ek_bytes })
    }
}

/// Simple nominal group implementation using modular arithmetic
pub struct TestGroup;

pub struct TestScalar {
    pub value: u64,
}

impl AsRef<[u8]> for TestScalar {
    fn as_ref(&self) -> &[u8] {
        // Return the value as bytes (little-endian)
        unsafe { std::slice::from_raw_parts(&self.value as *const u64 as *const u8, 8) }
    }
}

impl TryFrom<&[u8]> for TestScalar {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 8 {
            return Err(());
        }
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(bytes);
        let value = u64::from_le_bytes(value_bytes);
        Ok(TestScalar { value })
    }
}

pub struct TestElement {
    pub value: u64,
}

impl AsRef<[u8]> for TestElement {
    fn as_ref(&self) -> &[u8] {
        // Return the value as bytes (little-endian)
        unsafe { std::slice::from_raw_parts(&self.value as *const u64 as *const u8, 8) }
    }
}

impl TryFrom<&[u8]> for TestElement {
    type Error = ();
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 8 {
            return Err(());
        }
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(bytes);
        let value = u64::from_le_bytes(value_bytes);
        Ok(TestElement { value })
    }
}

impl NominalGroup for TestGroup {
    const SEED_LENGTH: usize = 8;
    const SCALAR_LENGTH: usize = 8;
    const ELEMENT_LENGTH: usize = 8;
    const SHARED_SECRET_LENGTH: usize = 32;
    
    type Scalar = TestScalar;
    type Element = TestElement;
    type Error = ();
    
    fn generator() -> Self::Element {
        TestElement { value: 5 } // Simple generator
    }
    
    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element {
        // Simple modular exponentiation: p^x mod large_prime
        let large_prime = 2147483647u64; // 2^31 - 1, a Mersenne prime
        let mut result = 1u64;
        let mut base = p.value % large_prime;
        let mut exp = x.value;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base) % large_prime;
            }
            exp /= 2;
            base = (base * base) % large_prime;
        }
        
        TestElement { value: result }
    }
    
    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, Self::Error> {
        if seed.len() != Self::SEED_LENGTH {
            return Err(());
        }
        
        // Convert seed bytes to u64
        let mut value = 0u64;
        for (i, &byte) in seed.iter().enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        
        // Ensure non-zero and within reasonable range
        if value == 0 { value = 1; }
        value = value % 1000000007; // Large prime to keep scalars reasonable
        
        Ok(TestScalar { value })
    }
    
    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8> {
        // Convert element to 32-byte shared secret using simple expansion
        let mut shared_secret = Vec::with_capacity(Self::SHARED_SECRET_LENGTH);
        let element_bytes = p.value.to_le_bytes();
        
        // Repeat and transform element bytes to fill shared secret
        for i in 0..Self::SHARED_SECRET_LENGTH {
            let base_byte = element_bytes[i % 8];
            let transformed = base_byte.wrapping_mul(17).wrapping_add(i as u8) ^ 0x33;
            shared_secret.push(transformed);
        }
        
        shared_secret
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use rand::rng;
    
    #[test]
    fn test_kdf() {
        test_kdf_all::<TestKdf>();
    }
    
    #[test]
    fn test_prg() {
        test_prg_all::<TestPrg>();
    }
    
    #[test]
    fn test_kem_roundtrip() {
        let mut rng = rng();
        test_kem_all::<TestKem, _>(&mut rng);
    }
    
    #[test]
    fn test_group_operations() {
        test_group_all::<TestGroup>();
    }
}

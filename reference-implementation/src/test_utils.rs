//! Generic test utilities for trait implementations
//!
//! This module provides reusable test functions that can be used to verify
//! any implementation of the KEM, KDF, PRG, and NominalGroup traits.

use crate::traits::{AsBytes, EncapsDerand, Kdf, Kem, NominalGroup, Prg};
use rand::CryptoRng;

/// Generic test for KDF determinism and output length
pub fn test_kdf_basic<K: Kdf>() {
    // Create test input of the correct length
    let mut input = vec![0u8; K::INPUT_LENGTH];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(42);
    }

    // Test output length
    let output = K::kdf(&input).expect("KDF should succeed with valid input");
    assert_eq!(output.len(), K::OUTPUT_LENGTH, "KDF output length mismatch");

    // Test determinism
    let output2 = K::kdf(&input).expect("KDF should be deterministic");
    assert_eq!(output, output2, "KDF should be deterministic");

    // Test different inputs produce different outputs (if input length > 0)
    if K::INPUT_LENGTH > 0 {
        let mut input2 = input.clone();
        input2[0] = input2[0].wrapping_add(1);
        let output3 = K::kdf(&input2).expect("KDF should work with different input");
        assert_ne!(
            output, output3,
            "Different inputs should produce different outputs"
        );
    }
}

/// Generic test for PRG determinism, output length, and expansion
pub fn test_prg_basic<P: Prg>() {
    // Create test seed of the correct length
    let mut seed = vec![0u8; P::INPUT_LENGTH];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(23).wrapping_add(77);
    }

    // Test output length and expansion
    let output = P::prg(&seed).expect("PRG should succeed with valid seed");
    assert_eq!(output.len(), P::OUTPUT_LENGTH, "PRG output length mismatch");
    assert!(
        P::OUTPUT_LENGTH > P::INPUT_LENGTH,
        "PRG should expand input"
    );

    // Test determinism
    let output2 = P::prg(&seed).expect("PRG should be deterministic");
    assert_eq!(output, output2, "PRG should be deterministic");

    // Test different seeds produce different outputs (if input length > 0)
    if P::INPUT_LENGTH > 0 {
        let mut seed2 = seed.clone();
        seed2[0] = seed2[0].wrapping_add(1);
        let output3 = P::prg(&seed2).expect("PRG should work with different seed");
        assert_ne!(
            output, output3,
            "Different seeds should produce different outputs"
        );
    }
}

/// Generic test for KEM key generation and serialization
pub fn test_kem_key_generation<K: Kem, R: CryptoRng>(rng: &mut R)
where
    for<'a> <K::EncapsulationKey as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    for<'a> <K::DecapsulationKey as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    // Test random key generation
    let (ek, dk) = K::generate_key_pair(rng).expect("Key generation should succeed");

    // Test serialization lengths
    let ek_bytes = ek.as_bytes();
    let dk_bytes = dk.as_bytes();

    assert_eq!(
        ek_bytes.len(),
        K::ENCAPSULATION_KEY_LENGTH,
        "Encapsulation key serialization length mismatch"
    );
    assert_eq!(
        dk_bytes.len(),
        K::DECAPSULATION_KEY_LENGTH,
        "Decapsulation key serialization length mismatch"
    );

    // Test deserialization roundtrip
    let ek2 = K::EncapsulationKey::try_from(ek_bytes)
        .expect("Encapsulation key deserialization should succeed");
    let dk2 = K::DecapsulationKey::try_from(dk_bytes)
        .expect("Decapsulation key deserialization should succeed");

    let ek2_bytes = ek2.as_bytes();
    let dk2_bytes = dk2.as_bytes();

    assert_eq!(
        ek_bytes, ek2_bytes,
        "Encapsulation key serialization should be stable"
    );
    assert_eq!(
        dk_bytes, dk2_bytes,
        "Decapsulation key serialization should be stable"
    );

    // Test to_encapsulation_key
    let ek3 = K::to_encapsulation_key(&dk).expect("to_encapsulation_key should succeed");
    let ek3_bytes = ek3.as_bytes();
    assert_eq!(
        ek_bytes, ek3_bytes,
        "to_encapsulation_key should produce consistent result"
    );
}

/// Generic test for KEM deterministic key derivation
pub fn test_kem_deterministic_derivation<K: Kem>() {
    // Create test seed of the correct length
    let mut seed = vec![0u8; K::SEED_LENGTH];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(13);
    }

    // Test deterministic key derivation
    let (ek1, dk1) = K::derive_key_pair(&seed).expect("Key derivation should succeed");
    let (ek2, dk2) = K::derive_key_pair(&seed).expect("Key derivation should be deterministic");

    let ek1_bytes = ek1.as_bytes();
    let ek2_bytes = ek2.as_bytes();
    let dk1_bytes = dk1.as_bytes();
    let dk2_bytes = dk2.as_bytes();

    assert_eq!(
        ek1_bytes, ek2_bytes,
        "Deterministic key derivation should produce same encapsulation key"
    );
    assert_eq!(
        dk1_bytes, dk2_bytes,
        "Deterministic key derivation should produce same decapsulation key"
    );
}

/// Generic test for KEM encapsulation/decapsulation roundtrip
pub fn test_kem_roundtrip<K: Kem, R: CryptoRng>(rng: &mut R)
where
    for<'a> <K::Ciphertext as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    // Generate key pair
    let (ek, dk) = K::generate_key_pair(rng).expect("Key generation should succeed");

    // Test encapsulation
    let (ct, ss1) = K::encaps(&ek, rng).expect("Encapsulation should succeed");

    // Test serialization lengths
    let ct_bytes = ct.as_bytes();
    let ss1_bytes = ss1.as_bytes();

    assert_eq!(
        ct_bytes.len(),
        K::CIPHERTEXT_LENGTH,
        "Ciphertext serialization length mismatch"
    );
    assert_eq!(
        ss1_bytes.len(),
        K::SHARED_SECRET_LENGTH,
        "Shared secret serialization length mismatch"
    );

    // Test decapsulation
    let ss2 = K::decaps(&dk, &ct).expect("Decapsulation should succeed");
    let ss2_bytes = ss2.as_bytes();

    assert_eq!(
        ss1_bytes, ss2_bytes,
        "Encapsulation and decapsulation should produce same shared secret"
    );

    // Test ciphertext deserialization roundtrip
    let ct2 = K::Ciphertext::try_from(ct_bytes).expect("Ciphertext deserialization should succeed");
    let ss3 =
        K::decaps(&dk, &ct2).expect("Decapsulation with deserialized ciphertext should succeed");
    let ss3_bytes = ss3.as_bytes();

    assert_eq!(
        ss1_bytes, ss3_bytes,
        "Deserialized ciphertext should work correctly"
    );
}

/// Generic test for KEM deterministic encapsulation
pub fn test_kem_deterministic_encaps<K: Kem + EncapsDerand, R: CryptoRng>(rng: &mut R) {
    // Generate key pair
    let (ek, dk) = K::generate_key_pair(rng).expect("Key generation should succeed");

    // Create deterministic randomness
    let randomness = vec![42u8; 64]; // Should be enough for most KEMs

    // Test deterministic encapsulation
    let (ct1, ss1) =
        K::encaps_derand(&ek, &randomness).expect("Deterministic encapsulation should succeed");
    let (ct2, ss2) = K::encaps_derand(&ek, &randomness)
        .expect("Deterministic encapsulation should be repeatable");

    let ct1_bytes = ct1.as_bytes();
    let ct2_bytes = ct2.as_bytes();
    let ss1_bytes = ss1.as_bytes();
    let ss2_bytes = ss2.as_bytes();

    assert_eq!(
        ct1_bytes, ct2_bytes,
        "Deterministic encapsulation should produce same ciphertext"
    );
    assert_eq!(
        ss1_bytes, ss2_bytes,
        "Deterministic encapsulation should produce same shared secret"
    );

    // Test that it decapsulates correctly
    let ss3 = K::decaps(&dk, &ct1).expect("Decapsulation should succeed");
    let ss3_bytes = ss3.as_bytes();

    assert_eq!(
        ss1_bytes, ss3_bytes,
        "Deterministic encapsulation should be compatible with decapsulation"
    );
}

/// Generic test for NominalGroup basic operations
pub fn test_group_basic_operations<G: NominalGroup>() {
    // Test generator
    let generator = G::generator();
    let gen_bytes = generator.as_bytes();
    assert_eq!(
        gen_bytes.len(),
        G::ELEMENT_LENGTH,
        "Generator serialization length mismatch"
    );

    // Test scalar generation
    let mut seed = vec![0u8; G::SEED_LENGTH];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(41).wrapping_add(29);
    }

    let scalar = G::random_scalar(&seed).expect("Scalar generation should succeed");
    let scalar_bytes = scalar.as_bytes();
    assert_eq!(
        scalar_bytes.len(),
        G::SCALAR_LENGTH,
        "Scalar serialization length mismatch"
    );

    // Test exponentiation
    let element = G::exp(&generator, &scalar);
    let elem_bytes = element.as_bytes();
    assert_eq!(
        elem_bytes.len(),
        G::ELEMENT_LENGTH,
        "Element serialization length mismatch"
    );

    // Test shared secret extraction
    let shared_secret = G::element_to_shared_secret(&element);
    assert_eq!(
        shared_secret.len(),
        G::SHARED_SECRET_LENGTH,
        "Shared secret length mismatch"
    );
}

/// Generic test for NominalGroup serialization roundtrips
pub fn test_group_serialization<G: NominalGroup>()
where
    for<'a> <G::Scalar as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    for<'a> <G::Element as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    // Test scalar serialization roundtrip
    let seed = vec![42u8; G::SEED_LENGTH];
    let scalar1 = G::random_scalar(&seed).expect("Scalar generation should succeed");
    let scalar_bytes = scalar1.as_bytes();
    let scalar2 = G::Scalar::try_from(scalar_bytes).expect("Scalar deserialization should succeed");
    let scalar2_bytes = scalar2.as_bytes();

    assert_eq!(
        scalar_bytes, scalar2_bytes,
        "Scalar serialization should be stable"
    );

    // Test element serialization roundtrip
    let generator = G::generator();
    let gen_bytes = generator.as_bytes();
    let gen2 = G::Element::try_from(gen_bytes).expect("Element deserialization should succeed");
    let gen2_bytes = gen2.as_bytes();

    assert_eq!(
        gen_bytes, gen2_bytes,
        "Element serialization should be stable"
    );

    // Test exponentiation result serialization
    let element1 = G::exp(&generator, &scalar1);
    let elem_bytes = element1.as_bytes();
    let element2 =
        G::Element::try_from(elem_bytes).expect("Element deserialization should succeed");
    let elem2_bytes = element2.as_bytes();

    assert_eq!(
        elem_bytes, elem2_bytes,
        "Exponentiation result serialization should be stable"
    );
}

/// Generic test for NominalGroup Diffie-Hellman properties
pub fn test_group_diffie_hellman<G: NominalGroup>() {
    let generator = G::generator();

    // Generate two scalars
    let seed_a = vec![1u8; G::SEED_LENGTH];
    let seed_b = vec![2u8; G::SEED_LENGTH];

    let scalar_a = G::random_scalar(&seed_a).expect("Scalar A generation should succeed");
    let scalar_b = G::random_scalar(&seed_b).expect("Scalar B generation should succeed");

    // Compute public keys
    let public_a = G::exp(&generator, &scalar_a);
    let public_b = G::exp(&generator, &scalar_b);

    // Compute shared secrets (should be equal due to DH property)
    let shared_ab = G::exp(&public_b, &scalar_a);
    let shared_ba = G::exp(&public_a, &scalar_b);

    let secret_ab = G::element_to_shared_secret(&shared_ab);
    let secret_ba = G::element_to_shared_secret(&shared_ba);

    assert_eq!(
        secret_ab, secret_ba,
        "Diffie-Hellman shared secrets should be equal"
    );

    // Test deterministic scalar generation
    let scalar_a2 = G::random_scalar(&seed_a).expect("Scalar generation should be deterministic");
    let scalar_a_bytes = scalar_a.as_bytes();
    let scalar_a2_bytes = scalar_a2.as_bytes();

    assert_eq!(
        scalar_a_bytes, scalar_a2_bytes,
        "Scalar generation should be deterministic"
    );
}

/// Run all KDF tests for a given implementation
pub fn test_kdf_all<K: Kdf>() {
    test_kdf_basic::<K>();
}

/// Run all PRG tests for a given implementation  
pub fn test_prg_all<P: Prg>() {
    test_prg_basic::<P>();
}

/// Run all KEM tests for a given implementation
pub fn test_kem_all<K: Kem + EncapsDerand, R: CryptoRng>(rng: &mut R)
where
    for<'a> <K::EncapsulationKey as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    for<'a> <K::DecapsulationKey as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    for<'a> <K::Ciphertext as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    test_kem_key_generation::<K, R>(rng);
    test_kem_deterministic_derivation::<K>();
    test_kem_roundtrip::<K, R>(rng);
    test_kem_deterministic_encaps::<K, R>(rng);
}

/// Run all NominalGroup tests for a given implementation
pub fn test_group_all<G: NominalGroup>()
where
    for<'a> <G::Scalar as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    for<'a> <G::Element as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    test_group_basic_operations::<G>();
    test_group_serialization::<G>();
    test_group_diffie_hellman::<G>();
}

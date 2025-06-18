use crate::error::KemError;

/// Trait for types that can be converted to byte slices
pub trait AsBytes {
    /// Convert to a byte slice
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for Vec<u8> {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

/// Key Derivation Function (KDF) trait
///
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait Kdf {
    /// The length in bytes of an input to this KDF
    const INPUT_LENGTH: usize;

    /// The length in bytes of an output from this KDF
    const OUTPUT_LENGTH: usize;

    /// Produce a byte string of length OUTPUT_LENGTH from an input byte string
    fn kdf(input: &[u8]) -> Vec<u8>;
}

/// Pseudorandom Generator (PRG) trait
///
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait Prg {
    /// The length in bytes of an input to this PRG
    const INPUT_LENGTH: usize;

    /// The length in bytes of an output from this PRG (longer than INPUT_LENGTH)
    const OUTPUT_LENGTH: usize;

    /// Produce a byte string of length OUTPUT_LENGTH from an input seed
    fn prg(seed: &[u8]) -> Vec<u8>;
}

/// Key Encapsulation Mechanism (KEM) trait
///
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait Kem {
    /// The length in bytes of a key seed (input to derive_key_pair)
    const SEED_LENGTH: usize;

    /// The length in bytes of a public encapsulation key
    const ENCAPSULATION_KEY_LENGTH: usize;

    /// The length in bytes of a secret decapsulation key
    const DECAPSULATION_KEY_LENGTH: usize;

    /// The length in bytes of a ciphertext produced by encaps
    const CIPHERTEXT_LENGTH: usize;

    /// The length in bytes of a shared secret produced by encaps or decaps
    const SHARED_SECRET_LENGTH: usize;

    /// Public encapsulation key type
    type EncapsulationKey: AsBytes + for<'a> From<&'a [u8]>;

    /// Secret decapsulation key type
    type DecapsulationKey: AsBytes + for<'a> From<&'a [u8]>;

    /// Ciphertext type
    type Ciphertext: AsBytes + for<'a> From<&'a [u8]>;

    /// Shared secret type
    type SharedSecret: AsBytes;

    /// Generate a random key pair
    ///
    /// Takes a cryptographically secure randomness source and returns (public_key, secret_key)
    fn generate_key_pair<R: rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError>;

    /// Derive a key pair from a seed
    ///
    /// Takes a seed of length SEED_LENGTH and deterministically generates a key pair
    fn derive_key_pair(
        seed: &[u8],
    ) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), KemError>;

    /// Encapsulate a shared secret
    ///
    /// Takes a public encapsulation key and randomness source, returns (ciphertext, shared_secret)
    fn encaps<R: rand::CryptoRng>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError>;

    /// Decapsulate a shared secret
    ///
    /// Takes a secret decapsulation key and ciphertext, returns the shared secret
    fn decaps(
        dk: &Self::DecapsulationKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, KemError>;

    /// Derive encapsulation key from decapsulation key
    fn to_encapsulation_key(
        dk: &Self::DecapsulationKey,
    ) -> Result<Self::EncapsulationKey, KemError>;
}

/// Trait for KEMs that support deterministic encapsulation
pub trait EncapsDerand: Kem {
    /// The length in bytes of randomness required for deterministic encapsulation
    const RANDOMNESS_LENGTH: usize;

    /// Deterministic encapsulation (for testing)
    ///
    /// Takes a public encapsulation key and randomness, returns (ciphertext, shared_secret)
    fn encaps_derand(
        ek: &Self::EncapsulationKey,
        randomness: &[u8],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), KemError>;
}

/// Nominal Group trait
///
/// Abstract model of elliptic curve groups for Diffie-Hellman key agreement
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait NominalGroup {
    /// The length in bytes of a seed (input to RandomScalar)
    const SEED_LENGTH: usize;

    /// The length in bytes of a scalar
    const SCALAR_LENGTH: usize;

    /// The length in bytes of a serialized group element
    const ELEMENT_LENGTH: usize;

    /// The length in bytes of a shared secret produced by ElementToSharedSecret
    const SHARED_SECRET_LENGTH: usize;

    /// Scalar type
    type Scalar: AsBytes + for<'a> From<&'a [u8]>;

    /// Group element type
    type Element: AsBytes + for<'a> From<&'a [u8]>;

    /// Distinguished basis element
    fn generator() -> Self::Element;

    /// Exponentiation: produces element q = p^x
    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element;

    /// Produce a uniform pseudo-random scalar from a seed
    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, KemError>;

    /// Extract a shared secret from a group element
    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8>;
}

/// Hybrid KEM Label trait
///
/// Provides a label to identify the specific combination of constituent algorithms
/// used in a hybrid KEM construction.
pub trait HybridKemLabel {
    /// Label used to identify the specific combination of constituents
    const LABEL: &'static [u8];
}

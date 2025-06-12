/// Key Derivation Function (KDF) trait
/// 
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait Kdf {
    /// The length in bytes of an input to this KDF
    const INPUT_LENGTH: usize;
    
    /// The length in bytes of an output from this KDF
    const OUTPUT_LENGTH: usize;
    
    /// Error type for KDF operations
    type Error;
    
    /// Produce a byte string of length OUTPUT_LENGTH from an input byte string
    fn kdf(input: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Pseudorandom Generator (PRG) trait
/// 
/// Based on the interface described in draft-irtf-cfrg-hybrid-kems
pub trait Prg {
    /// The length in bytes of an input to this PRG
    const INPUT_LENGTH: usize;
    
    /// The length in bytes of an output from this PRG (longer than INPUT_LENGTH)
    const OUTPUT_LENGTH: usize;
    
    /// Error type for PRG operations
    type Error;
    
    /// Produce a byte string of length OUTPUT_LENGTH from an input seed
    fn prg(seed: &[u8]) -> Result<Vec<u8>, Self::Error>;
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
    type EncapsulationKey;
    
    /// Secret decapsulation key type
    type DecapsulationKey;
    
    /// Ciphertext type
    type Ciphertext;
    
    /// Shared secret type
    type SharedSecret;
    
    /// Error type for KEM operations
    type Error;

    /// Generate a random key pair
    /// 
    /// Takes a cryptographically secure randomness source and returns (public_key, secret_key)
    fn generate_key_pair<R: rand::CryptoRng>(rng: &mut R) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error>;

    /// Derive a key pair from a seed
    /// 
    /// Takes a seed of length SEED_LENGTH and deterministically generates a key pair
    fn derive_key_pair(seed: &[u8]) -> Result<(Self::EncapsulationKey, Self::DecapsulationKey), Self::Error>;

    /// Encapsulate a shared secret
    /// 
    /// Takes a public encapsulation key and randomness source, returns (ciphertext, shared_secret)
    fn encaps<R: rand::CryptoRng>(ek: &Self::EncapsulationKey, rng: &mut R) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;

    /// Decapsulate a shared secret
    /// 
    /// Takes a secret decapsulation key and ciphertext, returns the shared secret
    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, Self::Error>;

    /// Deterministic encapsulation (for testing)
    /// 
    /// Takes a public encapsulation key and randomness, returns (ciphertext, shared_secret)
    fn encaps_derand(ek: &Self::EncapsulationKey, randomness: &[u8]) -> Result<(Self::Ciphertext, Self::SharedSecret), Self::Error>;
    
    /// Serialize encapsulation key to bytes
    fn serialize_encapsulation_key(ek: &Self::EncapsulationKey) -> &[u8];
    
    /// Serialize decapsulation key to bytes
    fn serialize_decapsulation_key(dk: &Self::DecapsulationKey) -> &[u8];
    
    /// Serialize ciphertext to bytes
    fn serialize_ciphertext(ct: &Self::Ciphertext) -> &[u8];
    
    /// Serialize shared secret to bytes
    fn serialize_shared_secret(ss: &Self::SharedSecret) -> &[u8];
    
    /// Deserialize encapsulation key from bytes
    fn deserialize_encapsulation_key(bytes: &[u8]) -> Result<Self::EncapsulationKey, Self::Error>;
    
    /// Deserialize decapsulation key from bytes
    fn deserialize_decapsulation_key(bytes: &[u8]) -> Result<Self::DecapsulationKey, Self::Error>;
    
    /// Deserialize ciphertext from bytes
    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, Self::Error>;
    
    /// Deserialize shared secret from bytes
    fn deserialize_shared_secret(bytes: &[u8]) -> Result<Self::SharedSecret, Self::Error>;
    
    /// Derive encapsulation key from decapsulation key
    fn to_encapsulation_key(dk: &Self::DecapsulationKey) -> Result<Self::EncapsulationKey, Self::Error>;
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
    type Scalar;
    
    /// Group element type
    type Element;
    
    /// Error type
    type Error;

    /// Distinguished basis element
    fn generator() -> Self::Element;

    /// Exponentiation: produces element q = p^x
    fn exp(p: &Self::Element, x: &Self::Scalar) -> Self::Element;

    /// Produce a uniform pseudo-random scalar from a seed
    fn random_scalar(seed: &[u8]) -> Result<Self::Scalar, Self::Error>;

    /// Extract a shared secret from a group element
    fn element_to_shared_secret(p: &Self::Element) -> Vec<u8>;

    /// Serialize scalar to bytes
    fn serialize_scalar(s: &Self::Scalar) -> &[u8];
    
    /// Serialize element to bytes
    fn serialize_element(e: &Self::Element) -> &[u8];
    
    /// Deserialize scalar from bytes
    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::Scalar, Self::Error>;
    
    /// Deserialize element from bytes
    fn deserialize_element(bytes: &[u8]) -> Result<Self::Element, Self::Error>;
}

/// Hybrid KEM Label trait
/// 
/// Provides a label to identify the specific combination of constituent algorithms
/// used in a hybrid KEM construction.
pub trait HybridKemLabel {
    /// Label used to identify the specific combination of constituents
    const LABEL: &'static [u8];
}

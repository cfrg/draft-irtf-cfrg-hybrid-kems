use std::error::Error;
use std::fmt;

/// KEM error type
///
/// Simplified error type for all KEM and Group operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// Error from traditional component (KEM or nominal group)
    TraditionalComponent,
    /// Error from post-quantum KEM component
    PostQuantumComponent,
    /// Error from KDF component
    Kdf,
    /// Error from PRG component
    Prg,
    /// Error from KeyHash KDF (used in PRE scheme)
    KeyHash,
    /// Invalid seed length provided
    InvalidSeedLength,
    /// Invalid input length provided
    InvalidInputLength,
    /// General cryptographic operation failure
    CryptographicFailure,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::TraditionalComponent => write!(f, "Traditional component error"),
            KemError::PostQuantumComponent => write!(f, "Post-quantum component error"),
            KemError::Kdf => write!(f, "KDF error"),
            KemError::Prg => write!(f, "PRG error"),
            KemError::KeyHash => write!(f, "KeyHash error"),
            KemError::InvalidSeedLength => write!(f, "Invalid seed length provided"),
            KemError::InvalidInputLength => write!(f, "Invalid input length provided"),
            KemError::CryptographicFailure => write!(f, "Cryptographic operation failure"),
        }
    }
}

impl Error for KemError {}

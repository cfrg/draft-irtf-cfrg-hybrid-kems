use std::error::Error;
use std::fmt;
use std::convert::Infallible;

/// Hybrid KEM error type
/// 
/// Generic error type that can be used by all hybrid KEM implementations
/// (GHP, PRE, QSF) to handle errors from their constituent components.
#[derive(Debug)]
pub enum HybridKemError<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError = Infallible> {
    /// Error from traditional component (KEM or nominal group)
    Traditional(TraditionalError),
    /// Error from post-quantum KEM component
    PostQuantum(PostQuantumError),
    /// Error from main KDF component
    Kdf(KdfError),
    /// Error from PRG component
    Prg(PrgError),
    /// Error from KeyHash KDF (used in PRE scheme)
    KeyHash(KeyHashError),
    /// Invalid seed length provided
    InvalidSeedLength,
    /// Invalid input length provided
    InvalidInputLength,
}

impl<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError> fmt::Display 
    for HybridKemError<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError>
where
    TraditionalError: fmt::Display,
    PostQuantumError: fmt::Display,
    KdfError: fmt::Display,
    PrgError: fmt::Display,
    KeyHashError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HybridKemError::Traditional(e) => write!(f, "Traditional component error: {}", e),
            HybridKemError::PostQuantum(e) => write!(f, "Post-quantum component error: {}", e),
            HybridKemError::Kdf(e) => write!(f, "KDF error: {}", e),
            HybridKemError::Prg(e) => write!(f, "PRG error: {}", e),
            HybridKemError::KeyHash(e) => write!(f, "KeyHash error: {}", e),
            HybridKemError::InvalidSeedLength => write!(f, "Invalid seed length provided"),
            HybridKemError::InvalidInputLength => write!(f, "Invalid input length provided"),
        }
    }
}

impl<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError> Error 
    for HybridKemError<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError>
where
    TraditionalError: Error + 'static,
    PostQuantumError: Error + 'static,
    KdfError: Error + 'static,
    PrgError: Error + 'static,
    KeyHashError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HybridKemError::Traditional(e) => Some(e),
            HybridKemError::PostQuantum(e) => Some(e),
            HybridKemError::Kdf(e) => Some(e),
            HybridKemError::Prg(e) => Some(e),
            HybridKemError::KeyHash(e) => Some(e),
            HybridKemError::InvalidSeedLength | HybridKemError::InvalidInputLength => None,
        }
    }
}

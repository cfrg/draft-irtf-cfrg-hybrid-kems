use std::error::Error;
use std::fmt;

/// KEM error type
///
/// Simplified error type for all KEM and Group operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// Error from traditional (KEM or nominal group)
    Traditional,
    /// Error from post-quantum KEM
    PostQuantum,
    /// Invalid input length provided
    InvalidInputLength,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::Traditional => write!(f, "Traditional error"),
            KemError::PostQuantum => write!(f, "Post-quantum error"),
            KemError::InvalidInputLength => write!(f, "Invalid input length provided"),
        }
    }
}

impl Error for KemError {}

/// Hybrid KEM error type
/// 
/// Generic error type that can be used by all hybrid KEM implementations
/// (GHP, PRE, QSF) to handle errors from their constituent components.
#[derive(Debug)]
pub enum HybridKemError<TraditionalError, PostQuantumError, KdfError, PrgError, KeyHashError = KdfError> {
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

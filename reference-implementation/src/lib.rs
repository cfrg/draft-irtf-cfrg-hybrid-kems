//! Hybrid KEM Reference Implementation
//!
//! This crate provides reference implementations of hybrid Key Encapsulation Mechanisms (KEMs)
//! as described in draft-irtf-cfrg-hybrid-kems.
//!
//! # Hybrid KEM Schemes
//!
//! This crate implements three hybrid KEM constructions:
//!
//! - **GHP**: Generic hybrid construction suitable for any traditional and post-quantum KEMs
//! - **PRE**: Performance optimization of GHP for large, frequently reused encapsulation keys
//! - **QSF**: Optimized construction for nominal groups with C2PRI post-quantum KEMs
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use hybrid_kem_ref::{traits::{Kem, HybridKemLabel}, ghp::GhpHybridKem};
//!
//! // Define a label for your hybrid KEM
//! struct MyLabel;
//! impl HybridKemLabel for MyLabel {
//!     const LABEL: &'static [u8] = b"MyHybridKem-v1";
//! }
//!
//! // Create a hybrid KEM with your choice of components
//! type MyHybridKem = GhpHybridKem<TraditionalKem, PostQuantumKem, Kdf, Prg, MyLabel>;
//!
//! // Generate keys
//! let mut rng = rand::thread_rng();
//! let (ek, dk) = MyHybridKem::generate_key_pair(&mut rng)?;
//!
//! // Encapsulate
//! let (ct, ss1) = MyHybridKem::encaps(&ek, &mut rng)?;
//!
//! // Decapsulate
//! let ss2 = MyHybridKem::decaps(&dk, &ct)?;
//!
//! assert_eq!(ss1, ss2);
//! ```

pub mod error;
pub mod ghp;
pub mod pre;
pub mod qsf;
pub mod test_impls;
pub mod test_utils;
pub mod traits;
pub mod utils;

#[cfg(test)]
mod hybrid_tests;

// Re-export commonly used items
pub use error::KemError;
pub use traits::{EncapsDerand, HybridKemLabel, Kdf, Kem, NominalGroup, Prg};
pub use utils::HybridValue;

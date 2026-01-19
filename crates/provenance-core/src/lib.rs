//! # Provenance Core
//!
//! Core types and cryptographic primitives for the Provenance trust framework,
//! implementing the PIC (Provenance Identity Continuity) specification.
//!
//! ## Key Concepts
//!
//! - **PCA (Proof of Causal Authority)**: The authority state at execution hop i
//! - **PoC (Proof of Continuity)**: Cryptographic proof linking hops in the chain
//! - **Operation**: An authorized action on a resource
//! - **Trust Plane**: The CAT (Causal Authority Transition) service
//!
//! ## PIC Invariants
//!
//! 1. **Provenance**: Origin principal (p₀) is immutable throughout the chain
//! 2. **Identity**: Authority can only decrease (ops_{i+1} ⊆ ops_i)
//! 3. **Continuity**: Each hop must cryptographically prove causal link to predecessor

pub mod crypto;
pub mod error;
pub mod operation;
pub mod pca;
pub mod poc;
pub mod types;

pub use crypto::{CoseSigned, SignedPca, SignedPoc};
pub use error::{ProvenanceError, Result};
pub use operation::{Operation, OperationSet};
pub use pca::{ExecutorBinding, Pca, PcaBuilder, Provenance};
pub use poc::{Poc, PocBuilder, SuccessorRequest};
pub use types::{Constraints, PrincipalIdentifier, TemporalConstraints};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get the library version
pub fn version() -> &'static str {
    VERSION
}

//! Error types for the Provenance framework

use thiserror::Error;

/// Result type alias using ProvenanceError
pub type Result<T> = std::result::Result<T, ProvenanceError>;

/// Errors that can occur in the Provenance framework
#[derive(Error, Debug)]
pub enum ProvenanceError {
    /// PCA signature verification failed
    #[error("PCA signature verification failed: {0}")]
    PcaSignatureInvalid(String),

    /// PoC signature verification failed
    #[error("PoC signature verification failed: {0}")]
    PocSignatureInvalid(String),

    /// Monotonicity violation - ops expanded instead of contracted
    #[error("Monotonicity violation: operation '{0}' not in predecessor ops")]
    MonotonicityViolation(String),

    /// Origin principal mismatch - p_0 was modified
    #[error("Origin principal mismatch: expected '{expected}', got '{actual}'")]
    OriginMismatch { expected: String, actual: String },

    /// PCA has expired
    #[error("PCA expired at {0}")]
    PcaExpired(String),

    /// PCA not yet valid
    #[error("PCA not valid until {0}")]
    PcaNotYetValid(String),

    /// Missing predecessor PCA in PoC
    #[error("PoC missing predecessor PCA")]
    MissingPredecessor,

    /// Unknown executor key
    #[error("Unknown executor: {0}")]
    UnknownExecutor(String),

    /// Unknown CAT key
    #[error("Unknown CAT: {0}")]
    UnknownCat(String),

    /// Invalid operation format
    #[error("Invalid operation format: {0}")]
    InvalidOperation(String),

    /// COSE encoding/decoding error
    #[error("COSE error: {0}")]
    CoseError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Constraint violation
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
}

impl From<ed25519_dalek::SignatureError> for ProvenanceError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        ProvenanceError::CryptoError(err.to_string())
    }
}

impl From<serde_json::Error> for ProvenanceError {
    fn from(err: serde_json::Error) -> Self {
        ProvenanceError::SerializationError(err.to_string())
    }
}

impl From<coset::CoseError> for ProvenanceError {
    fn from(err: coset::CoseError) -> Self {
        ProvenanceError::CoseError(format!("{:?}", err))
    }
}

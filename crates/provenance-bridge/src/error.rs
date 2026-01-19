//! Error types for the Federation Bridge

use thiserror::Error;

/// Result type for Federation Bridge operations
pub type Result<T> = std::result::Result<T, BridgeError>;

/// Errors that can occur in the Federation Bridge
#[derive(Error, Debug)]
pub enum BridgeError {
    /// Credential validation failed
    #[error("Credential validation failed: {0}")]
    ValidationFailed(String),

    /// Credential has expired
    #[error("Credential expired at {0}")]
    Expired(String),

    /// Credential not yet valid
    #[error("Credential not valid until {0}")]
    NotYetValid(String),

    /// Invalid credential format
    #[error("Invalid credential format: {0}")]
    InvalidFormat(String),

    /// Unknown issuer
    #[error("Unknown issuer: {0}")]
    UnknownIssuer(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// JWKS fetch error
    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(String),

    /// Key not found in JWKS
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// API key not found
    #[error("API key not found")]
    ApiKeyNotFound,

    /// API key revoked
    #[error("API key has been revoked")]
    ApiKeyRevoked,

    /// Missing required claim
    #[error("Missing required claim: {0}")]
    MissingClaim(String),

    /// Invalid audience
    #[error("Invalid audience: expected {expected}, got {actual}")]
    InvalidAudience { expected: String, actual: String },

    /// HTTP error
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<jsonwebtoken::errors::Error> for BridgeError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => BridgeError::Expired("JWT expired".into()),
            ErrorKind::ImmatureSignature => BridgeError::NotYetValid("JWT not yet valid".into()),
            ErrorKind::InvalidSignature => BridgeError::InvalidSignature(err.to_string()),
            ErrorKind::InvalidToken => BridgeError::InvalidFormat(err.to_string()),
            ErrorKind::InvalidAudience => BridgeError::InvalidAudience {
                expected: "expected".into(),
                actual: "actual".into(),
            },
            _ => BridgeError::ValidationFailed(err.to_string()),
        }
    }
}

impl From<reqwest::Error> for BridgeError {
    fn from(err: reqwest::Error) -> Self {
        BridgeError::HttpError(err.to_string())
    }
}

impl From<serde_json::Error> for BridgeError {
    fn from(err: serde_json::Error) -> Self {
        BridgeError::InvalidFormat(err.to_string())
    }
}

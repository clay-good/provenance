//! Storage abstraction for Trust Plane
//!
//! This module provides a trait-based abstraction for key storage,
//! enabling both in-memory (default) and persistent (PostgreSQL) backends.
//!
//! Federation support requires persistent storage so that:
//! - Executor keys survive restarts
//! - CAT keys from federated Trust Planes are preserved
//! - Revocation lists are durable
//! - Multiple Trust Plane instances can share state

pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;

pub use memory::MemoryStore;
#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;

use async_trait::async_trait;
use provenance_core::crypto::PublicKey;
use std::fmt::Debug;

/// Error type for storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Key already exists: {0}")]
    AlreadyExists(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Connection error: {0}")]
    Connection(String),
}

/// Information about a registered CAT (Causal Authority Transition) Trust Plane
#[derive(Debug, Clone)]
pub struct CatInfo {
    /// Key ID
    pub kid: String,
    /// Public key bytes (32 bytes for Ed25519)
    pub public_key: Vec<u8>,
    /// Human-readable name of the Trust Plane
    pub name: Option<String>,
    /// URL endpoint for this Trust Plane (for discovery)
    pub endpoint: Option<String>,
    /// When this CAT was registered
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Whether this is the local CAT (self)
    pub is_local: bool,
}

/// Information about a registered executor
#[derive(Debug, Clone)]
pub struct ExecutorInfo {
    /// Key ID
    pub kid: String,
    /// Public key bytes (32 bytes for Ed25519)
    pub public_key: Vec<u8>,
    /// Service name that registered this executor
    pub service_name: Option<String>,
    /// When this executor was registered
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// When this registration expires (if any)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Revocation entry for a PCA or principal
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    /// Hash of the revoked PCA (SHA-256)
    pub pca_hash: Vec<u8>,
    /// Principal (p_0) whose authority is revoked (optional - for blanket revocation)
    pub principal: Option<String>,
    /// Reason for revocation
    pub reason: String,
    /// Who revoked this (admin identifier)
    pub revoked_by: String,
    /// When this was revoked
    pub revoked_at: chrono::DateTime<chrono::Utc>,
}

/// Storage backend trait for Trust Plane state
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait KeyStore: Send + Sync + Debug {
    // =========================================================================
    // Executor Key Management
    // =========================================================================

    /// Register an executor's public key
    async fn register_executor(&self, info: ExecutorInfo) -> Result<(), StorageError>;

    /// Get an executor's public key by key ID
    async fn get_executor(&self, kid: &str) -> Result<Option<ExecutorInfo>, StorageError>;

    /// Remove an executor's registration
    async fn unregister_executor(&self, kid: &str) -> Result<bool, StorageError>;

    /// List all registered executor key IDs
    async fn list_executors(&self) -> Result<Vec<String>, StorageError>;

    // =========================================================================
    // CAT Key Management (Federation)
    // =========================================================================

    /// Register a CAT (Trust Plane) public key
    async fn register_cat(&self, info: CatInfo) -> Result<(), StorageError>;

    /// Get a CAT's public key by key ID
    async fn get_cat(&self, kid: &str) -> Result<Option<CatInfo>, StorageError>;

    /// Remove a CAT registration
    async fn unregister_cat(&self, kid: &str) -> Result<bool, StorageError>;

    /// List all registered CAT key IDs
    async fn list_cats(&self) -> Result<Vec<String>, StorageError>;

    /// Get all federated CATs (excluding local)
    async fn list_federated_cats(&self) -> Result<Vec<CatInfo>, StorageError>;

    // =========================================================================
    // Revocation Management
    // =========================================================================

    /// Add a revocation entry
    async fn revoke(&self, entry: RevocationEntry) -> Result<(), StorageError>;

    /// Check if a PCA hash is revoked
    async fn is_revoked(&self, pca_hash: &[u8]) -> Result<bool, StorageError>;

    /// Check if a principal is revoked (blanket revocation)
    async fn is_principal_revoked(&self, principal: &str) -> Result<bool, StorageError>;

    /// Get revocation info for a PCA hash
    async fn get_revocation(&self, pca_hash: &[u8]) -> Result<Option<RevocationEntry>, StorageError>;

    /// List all revocations (for building revocation list)
    async fn list_revocations(&self) -> Result<Vec<RevocationEntry>, StorageError>;
}

/// Helper to convert ExecutorInfo to PublicKey
impl ExecutorInfo {
    pub fn to_public_key(&self) -> Result<PublicKey, StorageError> {
        if self.public_key.len() != 32 {
            return Err(StorageError::Serialization(format!(
                "Invalid public key length: {}, expected 32",
                self.public_key.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.public_key);
        PublicKey::from_bytes(&self.kid, &bytes)
            .map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

/// Helper to convert CatInfo to PublicKey
impl CatInfo {
    pub fn to_public_key(&self) -> Result<PublicKey, StorageError> {
        if self.public_key.len() != 32 {
            return Err(StorageError::Serialization(format!(
                "Invalid public key length: {}, expected 32",
                self.public_key.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.public_key);
        PublicKey::from_bytes(&self.kid, &bytes)
            .map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

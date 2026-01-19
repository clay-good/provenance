//! API Key Credential Handler
//!
//! Validates API keys against a backend (in-memory, Qiuth, etc.)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, warn};

use crate::bridge::CredentialHandler;
use crate::error::{BridgeError, Result};
use crate::types::{CredentialType, ValidatedCredential};

/// Information about a validated API key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// Unique identifier for the key
    pub key_id: String,

    /// Owner of the key (becomes part of principal)
    pub owner_id: String,

    /// Allowed scopes/operations
    #[serde(default)]
    pub scopes: Vec<String>,

    /// When the key expires (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether the key is active
    #[serde(default = "default_true")]
    pub active: bool,

    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

fn default_true() -> bool {
    true
}

impl ApiKeyInfo {
    /// Create a new API key info
    pub fn new(key_id: impl Into<String>, owner_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            owner_id: owner_id.into(),
            scopes: Vec::new(),
            expires_at: None,
            active: true,
            metadata: HashMap::new(),
        }
    }

    /// Set scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set expiration
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Backend trait for API key validation
///
/// Implement this trait to integrate with different key storage systems.
#[async_trait]
pub trait ApiKeyBackend: Send + Sync {
    /// Validate an API key and return its info
    async fn validate(&self, api_key: &str) -> Result<ApiKeyInfo>;

    /// Get a description of this backend
    fn description(&self) -> &str {
        "API key backend"
    }
}

/// In-memory API key backend for testing
///
/// Stores API keys in memory. Useful for development and testing.
pub struct InMemoryApiKeyBackend {
    keys: RwLock<HashMap<String, ApiKeyInfo>>,
}

impl InMemoryApiKeyBackend {
    /// Create a new in-memory backend
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Register an API key
    pub fn register_key(&self, api_key: impl Into<String>, info: ApiKeyInfo) {
        let mut keys = self.keys.write().unwrap();
        keys.insert(api_key.into(), info);
    }

    /// Revoke an API key
    pub fn revoke_key(&self, api_key: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        if let Some(info) = keys.get_mut(api_key) {
            info.active = false;
            true
        } else {
            false
        }
    }

    /// Remove an API key
    pub fn remove_key(&self, api_key: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        keys.remove(api_key).is_some()
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().unwrap();
        keys.keys().cloned().collect()
    }
}

impl Default for InMemoryApiKeyBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApiKeyBackend for InMemoryApiKeyBackend {
    async fn validate(&self, api_key: &str) -> Result<ApiKeyInfo> {
        let keys = self.keys.read().unwrap();

        let info = keys.get(api_key)
            .ok_or(BridgeError::ApiKeyNotFound)?;

        if !info.active {
            return Err(BridgeError::ApiKeyRevoked);
        }

        if let Some(exp) = info.expires_at {
            if exp < Utc::now() {
                return Err(BridgeError::Expired(exp.to_rfc3339()));
            }
        }

        Ok(info.clone())
    }

    fn description(&self) -> &str {
        "in-memory API key backend"
    }
}

/// Qiuth API key backend (stub for integration)
///
/// This will integrate with Qiuth for MFA-validated API key management.
#[allow(dead_code)] // Fields reserved for future Qiuth integration
pub struct QiuthBackend {
    /// Qiuth API endpoint
    endpoint: String,
    /// HTTP client
    http_client: reqwest::Client,
}

impl QiuthBackend {
    /// Create a new Qiuth backend
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl ApiKeyBackend for QiuthBackend {
    async fn validate(&self, _api_key: &str) -> Result<ApiKeyInfo> {
        // TODO: Implement actual Qiuth integration
        // Flow:
        // 1. Call Qiuth validation endpoint with API key
        // 2. Qiuth validates the key and checks MFA requirements
        // 3. Return validated key info with scopes

        warn!(
            endpoint = %self.endpoint,
            "Qiuth integration not yet implemented"
        );

        Err(BridgeError::Internal(
            "Qiuth integration not yet implemented".into()
        ))
    }

    fn description(&self) -> &str {
        "Qiuth API key backend"
    }
}

/// API Key Credential Handler
pub struct ApiKeyHandler {
    backend: Box<dyn ApiKeyBackend>,
}

impl ApiKeyHandler {
    /// Create a new API key handler with the given backend
    pub fn new<B: ApiKeyBackend + 'static>(backend: B) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    /// Create a handler with an in-memory backend (for testing)
    pub fn in_memory() -> (Self, InMemoryApiKeyBackend) {
        let backend = InMemoryApiKeyBackend::new();
        // Create a second reference for the caller to populate
        let handler_backend = InMemoryApiKeyBackend::new();
        (
            Self {
                backend: Box::new(backend),
            },
            handler_backend,
        )
    }
}

#[async_trait]
impl CredentialHandler for ApiKeyHandler {
    fn credential_type(&self) -> CredentialType {
        CredentialType::ApiKey
    }

    fn description(&self) -> &str {
        "API key handler"
    }

    async fn validate(&self, credential: &str) -> Result<ValidatedCredential> {
        debug!("Validating API key");

        // Validate against backend
        let info = self.backend.validate(credential).await?;

        // Build principal: "apikey:{owner_id}"
        let principal = format!("apikey:{}", info.owner_id);

        let mut validated = ValidatedCredential::new(principal)
            .with_scopes(info.scopes.clone())
            .with_claim("key_id", serde_json::json!(info.key_id))
            .with_claim("owner_id", serde_json::json!(info.owner_id));

        if let Some(exp) = info.expires_at {
            validated = validated.with_expires_at(exp);
        }

        for (key, value) in info.metadata {
            validated = validated.with_claim(key, value);
        }

        Ok(validated)
    }
}

/// Helper to create a shared in-memory backend
pub fn create_in_memory_handler() -> (ApiKeyHandler, std::sync::Arc<InMemoryApiKeyBackend>) {
    let backend = std::sync::Arc::new(InMemoryApiKeyBackend::new());
    let handler = ApiKeyHandler {
        backend: Box::new(InMemoryBackendWrapper(backend.clone())),
    };
    (handler, backend)
}

/// Wrapper to allow Arc<InMemoryApiKeyBackend> to implement ApiKeyBackend
struct InMemoryBackendWrapper(std::sync::Arc<InMemoryApiKeyBackend>);

#[async_trait]
impl ApiKeyBackend for InMemoryBackendWrapper {
    async fn validate(&self, api_key: &str) -> Result<ApiKeyInfo> {
        self.0.validate(api_key).await
    }

    fn description(&self) -> &str {
        self.0.description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_backend() {
        let backend = InMemoryApiKeyBackend::new();

        // Register a key
        backend.register_key(
            "sk_test_123",
            ApiKeyInfo::new("key-1", "user-alice")
                .with_scopes(vec!["read:claims:*".into()]),
        );

        // Validate
        let result = backend.validate("sk_test_123").await;
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.key_id, "key-1");
        assert_eq!(info.owner_id, "user-alice");
        assert_eq!(info.scopes, vec!["read:claims:*"]);
    }

    #[tokio::test]
    async fn test_unknown_key() {
        let backend = InMemoryApiKeyBackend::new();
        let result = backend.validate("unknown_key").await;
        assert!(matches!(result, Err(BridgeError::ApiKeyNotFound)));
    }

    #[tokio::test]
    async fn test_revoked_key() {
        let backend = InMemoryApiKeyBackend::new();
        backend.register_key("sk_test_456", ApiKeyInfo::new("key-2", "user-bob"));
        backend.revoke_key("sk_test_456");

        let result = backend.validate("sk_test_456").await;
        assert!(matches!(result, Err(BridgeError::ApiKeyRevoked)));
    }

    #[tokio::test]
    async fn test_expired_key() {
        let backend = InMemoryApiKeyBackend::new();

        let expired = Utc::now() - chrono::Duration::hours(1);
        backend.register_key(
            "sk_test_expired",
            ApiKeyInfo::new("key-3", "user-charlie")
                .with_expires_at(expired),
        );

        let result = backend.validate("sk_test_expired").await;
        assert!(matches!(result, Err(BridgeError::Expired(_))));
    }

    #[tokio::test]
    async fn test_handler_integration() {
        let (handler, backend) = create_in_memory_handler();

        backend.register_key(
            "sk_live_abc",
            ApiKeyInfo::new("key-prod", "org-acme")
                .with_scopes(vec!["read:*".into(), "write:claims:*".into()]),
        );

        let result = handler.validate("sk_live_abc").await;
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.principal, "apikey:org-acme");
        assert_eq!(validated.scopes, vec!["read:*", "write:claims:*"]);
    }
}

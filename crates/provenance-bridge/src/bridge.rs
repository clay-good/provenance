//! Federation Bridge - routes credentials to appropriate handlers

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

use crate::error::{BridgeError, Result};
use crate::types::{CredentialType, ValidatedCredential};

/// Trait for credential handlers
///
/// Each handler validates a specific type of credential and
/// extracts the principal and claims.
#[async_trait]
pub trait CredentialHandler: Send + Sync {
    /// Get the type of credential this handler processes
    fn credential_type(&self) -> CredentialType;

    /// Validate a credential and extract principal/claims
    ///
    /// # Arguments
    /// * `credential` - The raw credential string
    ///
    /// # Returns
    /// * `Ok(ValidatedCredential)` - Validated credential with principal
    /// * `Err(BridgeError)` - If validation fails
    async fn validate(&self, credential: &str) -> Result<ValidatedCredential>;

    /// Get a description of this handler (for logging)
    fn description(&self) -> &str {
        "credential handler"
    }
}

/// Federation Bridge - routes credentials to handlers
///
/// The bridge maintains a registry of credential handlers and
/// routes incoming credentials to the appropriate handler based
/// on the credential type.
pub struct FederationBridge {
    handlers: HashMap<CredentialType, Arc<dyn CredentialHandler>>,
}

impl FederationBridge {
    /// Create a new empty federation bridge
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a credential handler
    pub fn register_handler<H: CredentialHandler + 'static>(&mut self, handler: H) {
        let credential_type = handler.credential_type();
        info!(
            credential_type = %credential_type,
            description = handler.description(),
            "Registered credential handler"
        );
        self.handlers.insert(credential_type, Arc::new(handler));
    }

    /// Get a handler for a credential type
    pub fn get_handler(&self, credential_type: CredentialType) -> Option<Arc<dyn CredentialHandler>> {
        self.handlers.get(&credential_type).cloned()
    }

    /// Check if a handler is registered for a credential type
    pub fn has_handler(&self, credential_type: CredentialType) -> bool {
        self.handlers.contains_key(&credential_type)
    }

    /// List all registered credential types
    pub fn registered_types(&self) -> Vec<CredentialType> {
        self.handlers.keys().cloned().collect()
    }

    /// Validate a credential
    ///
    /// Routes to the appropriate handler based on credential type.
    ///
    /// # Arguments
    /// * `credential` - The raw credential string
    /// * `credential_type` - The type of credential
    ///
    /// # Returns
    /// * `Ok(ValidatedCredential)` - Validated credential
    /// * `Err(BridgeError)` - If validation fails or no handler found
    pub async fn validate(
        &self,
        credential: &str,
        credential_type: CredentialType,
    ) -> Result<ValidatedCredential> {
        let handler = self.handlers.get(&credential_type).ok_or_else(|| {
            warn!(credential_type = %credential_type, "No handler for credential type");
            BridgeError::ValidationFailed(format!(
                "No handler registered for credential type: {}",
                credential_type
            ))
        })?;

        let result = handler.validate(credential).await;

        match &result {
            Ok(validated) => {
                info!(
                    credential_type = %credential_type,
                    principal = %validated.principal,
                    "Credential validated successfully"
                );
            }
            Err(e) => {
                warn!(
                    credential_type = %credential_type,
                    error = %e,
                    "Credential validation failed"
                );
            }
        }

        result
    }

    /// Validate a credential with type detection
    ///
    /// Attempts to detect the credential type and validate it.
    /// Currently supports:
    /// - JWT (if starts with "eyJ")
    /// - API Key (otherwise)
    pub async fn validate_auto(&self, credential: &str) -> Result<ValidatedCredential> {
        let credential_type = self.detect_credential_type(credential);
        self.validate(credential, credential_type).await
    }

    /// Detect the credential type from the credential string
    fn detect_credential_type(&self, credential: &str) -> CredentialType {
        // JWT tokens start with base64-encoded header (typically "eyJ")
        if credential.starts_with("eyJ") && credential.contains('.') {
            CredentialType::Jwt
        } else {
            CredentialType::ApiKey
        }
    }
}

impl Default for FederationBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating a FederationBridge with handlers
pub struct FederationBridgeBuilder {
    bridge: FederationBridge,
}

impl FederationBridgeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            bridge: FederationBridge::new(),
        }
    }

    /// Add a credential handler
    pub fn with_handler<H: CredentialHandler + 'static>(mut self, handler: H) -> Self {
        self.bridge.register_handler(handler);
        self
    }

    /// Build the federation bridge
    pub fn build(self) -> FederationBridge {
        self.bridge
    }
}

impl Default for FederationBridgeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHandler {
        credential_type: CredentialType,
    }

    #[async_trait]
    impl CredentialHandler for MockHandler {
        fn credential_type(&self) -> CredentialType {
            self.credential_type
        }

        async fn validate(&self, credential: &str) -> Result<ValidatedCredential> {
            Ok(ValidatedCredential::new(format!("mock:{}", credential)))
        }

        fn description(&self) -> &str {
            "mock handler"
        }
    }

    #[tokio::test]
    async fn test_bridge_registration() {
        let mut bridge = FederationBridge::new();
        bridge.register_handler(MockHandler {
            credential_type: CredentialType::Mock,
        });

        assert!(bridge.has_handler(CredentialType::Mock));
        assert!(!bridge.has_handler(CredentialType::Jwt));
    }

    #[tokio::test]
    async fn test_bridge_validation() {
        let mut bridge = FederationBridge::new();
        bridge.register_handler(MockHandler {
            credential_type: CredentialType::Mock,
        });

        let result = bridge.validate("test-cred", CredentialType::Mock).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().principal, "mock:test-cred");
    }

    #[tokio::test]
    async fn test_bridge_missing_handler() {
        let bridge = FederationBridge::new();
        let result = bridge.validate("test", CredentialType::Jwt).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_credential_type_detection() {
        let bridge = FederationBridge::new();

        // JWT-like string
        assert_eq!(
            bridge.detect_credential_type("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"),
            CredentialType::Jwt
        );

        // API key
        assert_eq!(
            bridge.detect_credential_type("sk_live_abc123"),
            CredentialType::ApiKey
        );
    }

    #[test]
    fn test_builder() {
        let bridge = FederationBridgeBuilder::new()
            .with_handler(MockHandler {
                credential_type: CredentialType::Mock,
            })
            .build();

        assert!(bridge.has_handler(CredentialType::Mock));
    }
}

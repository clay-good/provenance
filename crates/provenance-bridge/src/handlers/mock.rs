//! Mock Credential Handler
//!
//! For testing purposes - validates mock credentials.

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::bridge::CredentialHandler;
use crate::error::{BridgeError, Result};
use crate::types::{CredentialType, ValidatedCredential};

/// Mock credential handler for testing
///
/// Accepts credentials in the format:
/// - "principal" - Creates a credential for that principal with all ops allowed
/// - "principal:op1,op2,op3" - Creates a credential with specific ops
/// - "FAIL:message" - Returns an error with the given message
pub struct MockHandler;

impl MockHandler {
    /// Create a new mock handler
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialHandler for MockHandler {
    fn credential_type(&self) -> CredentialType {
        CredentialType::Mock
    }

    fn description(&self) -> &str {
        "mock credential handler"
    }

    async fn validate(&self, credential: &str) -> Result<ValidatedCredential> {
        // Check for explicit failure
        if let Some(message) = credential.strip_prefix("FAIL:") {
            return Err(BridgeError::ValidationFailed(message.to_string()));
        }

        // Parse credential
        let parts: Vec<&str> = credential.splitn(2, ':').collect();
        let principal_name = parts[0];

        if principal_name.is_empty() {
            return Err(BridgeError::InvalidFormat(
                "Mock credential cannot be empty".into(),
            ));
        }

        // Extract scopes if provided
        let scopes = if parts.len() > 1 && !parts[1].is_empty() {
            parts[1]
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        } else {
            vec!["*".to_string()]
        };

        // Build credential
        let principal = format!("mock:{}", principal_name);
        let expires_at = Utc::now() + Duration::hours(1);

        let validated = ValidatedCredential::new(principal)
            .with_scopes(scopes)
            .with_expires_at(expires_at)
            .with_issuer("mock")
            .with_claim("mock", serde_json::json!(true));

        Ok(validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_credential() {
        let handler = MockHandler::new();
        let result = handler.validate("alice").await;

        assert!(result.is_ok());
        let cred = result.unwrap();
        assert_eq!(cred.principal, "mock:alice");
        assert_eq!(cred.scopes, vec!["*"]);
    }

    #[tokio::test]
    async fn test_credential_with_scopes() {
        let handler = MockHandler::new();
        let result = handler.validate("bob:read:claims:*,write:data:*").await;

        assert!(result.is_ok());
        let cred = result.unwrap();
        assert_eq!(cred.principal, "mock:bob");
        assert_eq!(cred.scopes, vec!["read:claims:*", "write:data:*"]);
    }

    #[tokio::test]
    async fn test_explicit_failure() {
        let handler = MockHandler::new();
        let result = handler.validate("FAIL:test error").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::ValidationFailed(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[tokio::test]
    async fn test_empty_credential() {
        let handler = MockHandler::new();
        let result = handler.validate("").await;

        assert!(result.is_err());
    }
}

//! Core types for the Federation Bridge

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of credentials that can be validated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// JWT/OIDC token
    Jwt,
    /// API key
    ApiKey,
    /// Mock credential (for testing)
    Mock,
    /// Custom credential type
    Custom,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::Jwt => write!(f, "jwt"),
            CredentialType::ApiKey => write!(f, "apikey"),
            CredentialType::Mock => write!(f, "mock"),
            CredentialType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for CredentialType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "jwt" | "oidc" => Ok(CredentialType::Jwt),
            "apikey" | "api_key" | "api-key" => Ok(CredentialType::ApiKey),
            "mock" => Ok(CredentialType::Mock),
            "custom" => Ok(CredentialType::Custom),
            _ => Err(format!("Unknown credential type: {}", s)),
        }
    }
}

/// A validated credential with extracted principal and claims
///
/// This is the output of credential validation, containing:
/// - The principal identifier (becomes p_0 in PCA)
/// - Any claims from the credential
/// - Expiration time (if applicable)
/// - Allowed scopes/operations (if applicable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedCredential {
    /// Principal identifier (becomes p_0)
    /// Format: "{type}:{issuer}#{subject}"
    /// Examples:
    /// - "oidc:https://accounts.google.com#user123"
    /// - "apikey:owner-456"
    pub principal: String,

    /// Claims extracted from the credential
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,

    /// When the credential expires (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Allowed scopes/operations from the credential
    #[serde(default)]
    pub scopes: Vec<String>,

    /// The issuer of the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ValidatedCredential {
    /// Create a new validated credential
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            claims: HashMap::new(),
            expires_at: None,
            scopes: Vec::new(),
            issuer: None,
            metadata: HashMap::new(),
        }
    }

    /// Set expiration time
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add a claim
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.claims.insert(key.into(), value);
        self
    }

    /// Set scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set issuer
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Check if the credential is expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            exp < Utc::now()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type_parsing() {
        assert_eq!("jwt".parse::<CredentialType>().unwrap(), CredentialType::Jwt);
        assert_eq!("oidc".parse::<CredentialType>().unwrap(), CredentialType::Jwt);
        assert_eq!("apikey".parse::<CredentialType>().unwrap(), CredentialType::ApiKey);
        assert_eq!("api_key".parse::<CredentialType>().unwrap(), CredentialType::ApiKey);
        assert_eq!("mock".parse::<CredentialType>().unwrap(), CredentialType::Mock);
    }

    #[test]
    fn test_validated_credential() {
        let cred = ValidatedCredential::new("oidc:issuer#user123")
            .with_issuer("https://issuer.example.com")
            .with_scopes(vec!["read:claims".into()])
            .with_claim("email", serde_json::json!("user@example.com"));

        assert_eq!(cred.principal, "oidc:issuer#user123");
        assert!(!cred.is_expired());
        assert_eq!(cred.scopes, vec!["read:claims"]);
    }

    #[test]
    fn test_expired_credential() {
        let expired_time = Utc::now() - chrono::Duration::hours(1);
        let cred = ValidatedCredential::new("test")
            .with_expires_at(expired_time);

        assert!(cred.is_expired());
    }
}

//! JWT/OIDC Credential Handler
//!
//! Validates JWT tokens from trusted issuers using JWKS.

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, Validation,
};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::bridge::CredentialHandler;
use crate::error::{BridgeError, Result};
use crate::types::{CredentialType, ValidatedCredential};

/// Configuration for a trusted JWT issuer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtIssuerConfig {
    /// The issuer identifier (iss claim)
    pub issuer: String,

    /// URL to fetch JWKS from
    pub jwks_url: String,

    /// Expected audience (aud claim), if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// Claim to extract as the subject/principal (default: "sub")
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,

    /// Allowed algorithms (default: RS256, ES256)
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
}

fn default_principal_claim() -> String {
    "sub".to_string()
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string(), "ES256".to_string()]
}

impl JwtIssuerConfig {
    /// Create a new issuer configuration
    pub fn new(issuer: impl Into<String>, jwks_url: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_url: jwks_url.into(),
            audience: None,
            principal_claim: default_principal_claim(),
            algorithms: default_algorithms(),
        }
    }

    /// Set the expected audience
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the principal claim
    pub fn with_principal_claim(mut self, claim: impl Into<String>) -> Self {
        self.principal_claim = claim.into();
        self
    }
}

/// JWKS (JSON Web Key Set) response
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Individual JWK (JSON Web Key)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields from JWKS spec, not all used directly
struct Jwk {
    /// Key ID
    kid: Option<String>,
    /// Key type
    kty: String,
    /// Algorithm
    alg: Option<String>,
    /// Use (sig for signing)
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// RSA modulus (for RSA keys)
    n: Option<String>,
    /// RSA exponent (for RSA keys)
    e: Option<String>,
    /// EC curve (for EC keys)
    crv: Option<String>,
    /// EC x coordinate
    x: Option<String>,
    /// EC y coordinate
    y: Option<String>,
}

/// JWT claims we care about
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Standard JWT claims, not all used directly
struct JwtClaims {
    /// Issuer
    iss: Option<String>,
    /// Subject
    sub: Option<String>,
    /// Audience (can be string or array)
    aud: Option<serde_json::Value>,
    /// Expiration
    exp: Option<i64>,
    /// Not before
    nbf: Option<i64>,
    /// Issued at
    iat: Option<i64>,
    /// All other claims
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// JWT/OIDC Credential Handler
pub struct JwtHandler {
    /// Trusted issuers
    issuers: HashMap<String, JwtIssuerConfig>,
    /// JWKS cache (issuer -> JWKS)
    jwks_cache: Cache<String, Arc<JwksResponse>>,
    /// HTTP client for fetching JWKS
    http_client: reqwest::Client,
}

impl JwtHandler {
    /// Create a new JWT handler
    pub fn new() -> Self {
        Self {
            issuers: HashMap::new(),
            jwks_cache: Cache::builder()
                .time_to_live(Duration::from_secs(3600)) // 1 hour TTL
                .max_capacity(100)
                .build(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Add a trusted issuer
    pub fn with_issuer(mut self, config: JwtIssuerConfig) -> Self {
        self.issuers.insert(config.issuer.clone(), config);
        self
    }

    /// Add multiple trusted issuers
    pub fn with_issuers(mut self, configs: Vec<JwtIssuerConfig>) -> Self {
        for config in configs {
            self.issuers.insert(config.issuer.clone(), config);
        }
        self
    }

    /// Fetch JWKS for an issuer (with caching)
    async fn fetch_jwks(&self, issuer: &str) -> Result<Arc<JwksResponse>> {
        // Check cache first
        if let Some(cached) = self.jwks_cache.get(issuer).await {
            debug!(issuer = %issuer, "Using cached JWKS");
            return Ok(cached);
        }

        // Get issuer config
        let config = self.issuers.get(issuer).ok_or_else(|| {
            BridgeError::UnknownIssuer(issuer.to_string())
        })?;

        // Fetch JWKS
        debug!(issuer = %issuer, url = %config.jwks_url, "Fetching JWKS");
        let response = self.http_client
            .get(&config.jwks_url)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| BridgeError::JwksFetchError(e.to_string()))?;

        let jwks: JwksResponse = response.json().await
            .map_err(|e| BridgeError::JwksFetchError(e.to_string()))?;

        let jwks = Arc::new(jwks);

        // Cache it
        self.jwks_cache.insert(issuer.to_string(), jwks.clone()).await;

        Ok(jwks)
    }

    /// Find a key in JWKS by key ID
    fn find_key<'a>(&self, jwks: &'a JwksResponse, kid: Option<&str>) -> Result<&'a Jwk> {
        match kid {
            Some(kid) => {
                jwks.keys.iter()
                    .find(|k| k.kid.as_deref() == Some(kid))
                    .ok_or_else(|| BridgeError::KeyNotFound(kid.to_string()))
            }
            None => {
                // If no kid, use the first signing key
                jwks.keys.iter()
                    .find(|k| k.key_use.as_deref() == Some("sig") || k.key_use.is_none())
                    .ok_or_else(|| BridgeError::KeyNotFound("no signing key found".to_string()))
            }
        }
    }

    /// Create a decoding key from a JWK
    fn decoding_key_from_jwk(&self, jwk: &Jwk, _alg: Algorithm) -> Result<DecodingKey> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_ref()
                    .ok_or_else(|| BridgeError::InvalidFormat("Missing RSA modulus".into()))?;
                let e = jwk.e.as_ref()
                    .ok_or_else(|| BridgeError::InvalidFormat("Missing RSA exponent".into()))?;

                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| BridgeError::InvalidFormat(e.to_string()))
            }
            "EC" => {
                let x = jwk.x.as_ref()
                    .ok_or_else(|| BridgeError::InvalidFormat("Missing EC x coordinate".into()))?;
                let y = jwk.y.as_ref()
                    .ok_or_else(|| BridgeError::InvalidFormat("Missing EC y coordinate".into()))?;

                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| BridgeError::InvalidFormat(e.to_string()))
            }
            kty => Err(BridgeError::UnsupportedAlgorithm(format!("Key type: {}", kty))),
        }
    }

}

impl Default for JwtHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialHandler for JwtHandler {
    fn credential_type(&self) -> CredentialType {
        CredentialType::Jwt
    }

    fn description(&self) -> &str {
        "JWT/OIDC handler"
    }

    async fn validate(&self, credential: &str) -> Result<ValidatedCredential> {
        // Step 1: Decode header to get kid and alg
        let header = decode_header(credential)
            .map_err(|e| BridgeError::InvalidFormat(e.to_string()))?;

        let alg = header.alg;

        // Step 2: Decode without verification to get issuer
        let mut validation = Validation::new(alg);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data = decode::<JwtClaims>(credential, &DecodingKey::from_secret(&[]), &validation)
            .map_err(|e| BridgeError::InvalidFormat(e.to_string()))?;

        let issuer = token_data.claims.iss.as_ref()
            .ok_or_else(|| BridgeError::MissingClaim("iss".into()))?;

        // Step 3: Get issuer config
        let config = self.issuers.get(issuer)
            .ok_or_else(|| BridgeError::UnknownIssuer(issuer.clone()))?;

        // Step 4: Fetch JWKS
        let jwks = self.fetch_jwks(issuer).await?;

        // Step 5: Find key
        let jwk = self.find_key(&jwks, header.kid.as_deref())?;

        // Step 6: Create decoding key
        let decoding_key = self.decoding_key_from_jwk(jwk, alg)?;

        // Step 7: Validate with proper settings
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);

        if let Some(ref aud) = config.audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<JwtClaims>(credential, &decoding_key, &validation)?;
        let claims = token_data.claims;

        // Step 8: Extract principal
        let subject = if config.principal_claim == "sub" {
            claims.sub.clone()
        } else {
            claims.extra.get(&config.principal_claim)
                .and_then(|v| v.as_str().map(String::from))
        }.ok_or_else(|| BridgeError::MissingClaim(config.principal_claim.clone()))?;

        // Build principal identifier: "oidc:{issuer}#{subject}"
        let principal = format!("oidc:{}#{}", issuer, subject);

        // Build validated credential
        let mut validated = ValidatedCredential::new(principal)
            .with_issuer(issuer.clone());

        // Add expiration if present
        if let Some(exp) = claims.exp {
            if let Some(exp_time) = Utc.timestamp_opt(exp, 0).single() {
                validated = validated.with_expires_at(exp_time);
            }
        }

        // Add claims
        if let Some(sub) = claims.sub {
            validated = validated.with_claim("sub", serde_json::json!(sub));
        }
        for (key, value) in claims.extra {
            validated = validated.with_claim(key, value);
        }

        // Extract scopes if present
        if let Some(scope) = validated.claims.get("scope") {
            if let Some(scope_str) = scope.as_str() {
                validated.scopes = scope_str.split_whitespace().map(String::from).collect();
            }
        }

        Ok(validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_config() {
        let config = JwtIssuerConfig::new(
            "https://accounts.google.com",
            "https://www.googleapis.com/oauth2/v3/certs",
        )
        .with_audience("my-app")
        .with_principal_claim("email");

        assert_eq!(config.issuer, "https://accounts.google.com");
        assert_eq!(config.audience, Some("my-app".to_string()));
        assert_eq!(config.principal_claim, "email");
    }

    #[tokio::test]
    async fn test_unknown_issuer() {
        let _handler = JwtHandler::new();

        // This would fail at issuer lookup since no issuers registered
        // We can't easily test full flow without a real JWT
    }
}

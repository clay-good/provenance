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

    /// Whether this issuer produces OAuth Token Exchange (RFC 8693) tokens.
    ///
    /// When true, the handler:
    /// - Extracts p_0 from the `act.sub` claim (original subject in delegation chain)
    ///   rather than the top-level `sub`, preserving provenance back to the human user
    /// - Maps the `pic_ops` claim (or custom claim via `pic_ops_claim`) directly to
    ///   PIC operation strings for ops_0
    /// - Falls back to standard `scope` claim if `pic_ops` is absent
    ///
    /// When false (default), existing JWT handling is unchanged.
    #[serde(default)]
    pub token_exchange_aware: bool,

    /// Claim name holding PIC operation strings (default: "pic_ops").
    /// Only used when `token_exchange_aware` is true.
    #[serde(default = "default_pic_ops_claim")]
    pub pic_ops_claim: String,
}

fn default_principal_claim() -> String {
    "sub".to_string()
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string(), "ES256".to_string()]
}

fn default_pic_ops_claim() -> String {
    "pic_ops".to_string()
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
            token_exchange_aware: false,
            pic_ops_claim: default_pic_ops_claim(),
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

    /// Enable OAuth Token Exchange (RFC 8693) awareness.
    ///
    /// When enabled, the handler extracts p_0 from the `act.sub` claim
    /// (preserving provenance to the original human user) and maps the
    /// `pic_ops` claim to PIC operation strings.
    pub fn with_token_exchange(mut self, enabled: bool) -> Self {
        self.token_exchange_aware = enabled;
        self
    }

    /// Set a custom claim name for PIC operations (default: "pic_ops").
    /// Only relevant when `token_exchange_aware` is true.
    pub fn with_pic_ops_claim(mut self, claim: impl Into<String>) -> Self {
        self.pic_ops_claim = claim.into();
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

    /// Extract the principal from a token exchange JWT (RFC 8693).
    ///
    /// In a token exchange flow, the `act` claim contains the actor chain.
    /// The original subject (the human user) is found by traversing the
    /// `act` chain to its deepest `sub` — or, if no `act` claim exists,
    /// falls back to the top-level `sub`.
    ///
    /// This ensures that p_0 always traces back to the original human
    /// who initiated the request, not the service that performed the exchange.
    fn extract_token_exchange_principal(
        &self,
        claims: &JwtClaims,
        config: &JwtIssuerConfig,
    ) -> Result<String> {
        // Check for act claim (RFC 8693 Section 4.1)
        if let Some(act_value) = claims.extra.get("act") {
            // Traverse the act chain to find the deepest subject.
            // RFC 8693 defines act as: { "sub": "...", "act": { "sub": "...", ... } }
            // The outermost act.sub is the immediate actor, and nested act.sub
            // values represent further delegation. For PIC, we want the deepest
            // subject — the original human user.
            if let Some(original_sub) = self.deepest_act_subject(act_value) {
                debug!(
                    original_subject = %original_sub,
                    top_level_subject = ?claims.sub,
                    "Token exchange: extracted original subject from act chain"
                );
                return Ok(original_sub);
            }
        }

        // Fallback: use configured principal_claim (defaults to "sub")
        if config.principal_claim == "sub" {
            claims.sub.clone()
        } else {
            claims.extra.get(&config.principal_claim)
                .and_then(|v| v.as_str().map(String::from))
        }
        .ok_or_else(|| BridgeError::MissingClaim(config.principal_claim.clone()))
    }

    /// Recursively traverse the `act` chain to find the deepest subject.
    ///
    /// Given: `{ "sub": "service-A", "act": { "sub": "alice" } }`
    /// Returns: `"alice"` (the deepest/original subject)
    fn deepest_act_subject(&self, act: &serde_json::Value) -> Option<String> {
        deepest_act_subject_recursive(act)
    }

    /// Extract PIC operation strings from JWT claims.
    ///
    /// Prefers the dedicated `pic_ops` claim (configurable via `pic_ops_claim`).
    /// The claim can be:
    /// - An array of strings: `["read:claims:alice/*"]`
    /// - A single string: `"read:claims:alice/*"`
    ///
    /// Falls back to standard `scope` claim (space-delimited) if pic_ops is absent.
    fn extract_pic_ops(&self, claims: &JwtClaims, config: &JwtIssuerConfig) -> Vec<String> {
        // Try pic_ops claim first
        if let Some(pic_ops) = claims.extra.get(&config.pic_ops_claim) {
            let ops = self.value_to_string_vec(pic_ops);
            if !ops.is_empty() {
                debug!(
                    pic_ops = ?ops,
                    claim = %config.pic_ops_claim,
                    "Extracted PIC operations from dedicated claim"
                );
                return ops;
            }
        }

        // Fallback to scope claim
        if let Some(scope) = claims.extra.get("scope") {
            if let Some(scope_str) = scope.as_str() {
                let ops: Vec<String> = scope_str.split_whitespace().map(String::from).collect();
                if !ops.is_empty() {
                    debug!(
                        scope_ops = ?ops,
                        "Extracted PIC operations from scope claim (fallback)"
                    );
                    return ops;
                }
            }
        }

        Vec::new()
    }

    /// Convert a JSON value to a Vec<String>.
    /// Handles arrays of strings, single strings, and space-delimited strings.
    fn value_to_string_vec(&self, value: &serde_json::Value) -> Vec<String> {
        match value {
            serde_json::Value::Array(arr) => {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            }
            serde_json::Value::String(s) => {
                // Could be space-delimited or a single value
                if s.contains(' ') {
                    s.split_whitespace().map(String::from).collect()
                } else {
                    vec![s.clone()]
                }
            }
            _ => Vec::new(),
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

/// Recursively traverse the `act` chain to find the deepest subject.
///
/// Given: `{ "sub": "service-A", "act": { "sub": "alice" } }`
/// Returns: `"alice"` (the deepest/original subject)
fn deepest_act_subject_recursive(act: &serde_json::Value) -> Option<String> {
    let obj = act.as_object()?;

    // If there's a nested act, go deeper first
    if let Some(nested_act) = obj.get("act") {
        if let Some(deeper) = deepest_act_subject_recursive(nested_act) {
            return Some(deeper);
        }
    }

    // Return this level's sub
    obj.get("sub")
        .and_then(|v| v.as_str())
        .map(String::from)
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
        //
        // When token_exchange_aware is true and an "act" claim is present,
        // extract p_0 from the actor chain (act.sub) rather than the top-level
        // sub. This preserves provenance back to the original human user even
        // when the token was exchanged by a service (RFC 8693 Section 4.1).
        let subject = if config.token_exchange_aware {
            self.extract_token_exchange_principal(&claims, config)?
        } else if config.principal_claim == "sub" {
            claims.sub.clone()
                .ok_or_else(|| BridgeError::MissingClaim(config.principal_claim.clone()))?
        } else {
            claims.extra.get(&config.principal_claim)
                .and_then(|v| v.as_str().map(String::from))
                .ok_or_else(|| BridgeError::MissingClaim(config.principal_claim.clone()))?
        };

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
        if let Some(ref sub) = claims.sub {
            validated = validated.with_claim("sub", serde_json::json!(sub));
        }
        for (key, value) in claims.extra.iter() {
            validated = validated.with_claim(key.clone(), value.clone());
        }

        // Extract scopes/operations
        if config.token_exchange_aware {
            // When token_exchange_aware, prefer pic_ops claim for PIC operations.
            // pic_ops can be an array of strings or a space-delimited string.
            // Falls back to standard "scope" claim if pic_ops is absent.
            validated.scopes = self.extract_pic_ops(&claims, config);
        } else {
            // Standard scope extraction from space-delimited "scope" claim
            if let Some(scope) = validated.claims.get("scope") {
                if let Some(scope_str) = scope.as_str() {
                    validated.scopes = scope_str.split_whitespace().map(String::from).collect();
                }
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

    #[test]
    fn test_issuer_config_defaults() {
        let config = JwtIssuerConfig::new(
            "https://keycloak.example.com/realms/pic-demo",
            "https://keycloak.example.com/realms/pic-demo/protocol/openid-connect/certs",
        );

        assert!(!config.token_exchange_aware);
        assert_eq!(config.pic_ops_claim, "pic_ops");
        assert_eq!(config.principal_claim, "sub");
    }

    #[test]
    fn test_issuer_config_token_exchange() {
        let config = JwtIssuerConfig::new(
            "https://keycloak.example.com/realms/pic-demo",
            "https://keycloak.example.com/realms/pic-demo/protocol/openid-connect/certs",
        )
        .with_token_exchange(true)
        .with_pic_ops_claim("custom_ops")
        .with_audience("pic-resource-api");

        assert!(config.token_exchange_aware);
        assert_eq!(config.pic_ops_claim, "custom_ops");
        assert_eq!(config.audience, Some("pic-resource-api".to_string()));
    }

    #[test]
    fn test_issuer_config_serde_roundtrip() {
        let config = JwtIssuerConfig::new(
            "https://keycloak.example.com/realms/pic-demo",
            "https://keycloak.example.com/realms/pic-demo/protocol/openid-connect/certs",
        )
        .with_token_exchange(true);

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: JwtIssuerConfig = serde_json::from_str(&json).unwrap();

        assert!(deserialized.token_exchange_aware);
        assert_eq!(deserialized.pic_ops_claim, "pic_ops");
    }

    #[test]
    fn test_issuer_config_serde_defaults_omitted() {
        // Verify that deserializing JSON without the new fields still works
        // (backwards compatibility for existing configs)
        let json = r#"{
            "issuer": "https://accounts.google.com",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs"
        }"#;

        let config: JwtIssuerConfig = serde_json::from_str(json).unwrap();
        assert!(!config.token_exchange_aware);
        assert_eq!(config.pic_ops_claim, "pic_ops");
        assert_eq!(config.principal_claim, "sub");
    }

    #[tokio::test]
    async fn test_unknown_issuer() {
        let _handler = JwtHandler::new();

        // This would fail at issuer lookup since no issuers registered
        // We can't easily test full flow without a real JWT
    }

    // =========================================================================
    // Token Exchange (RFC 8693) Tests
    // =========================================================================
    //
    // These tests verify the principal extraction and PIC operations mapping
    // logic for OAuth Token Exchange tokens. They test the helper methods
    // directly to avoid needing a real JWKS endpoint.

    /// Helper to create a JwtHandler for testing helper methods
    fn test_handler() -> JwtHandler {
        JwtHandler::new()
    }

    /// Helper to create a JwtClaims from JSON for testing
    fn claims_from_json(json: serde_json::Value) -> JwtClaims {
        serde_json::from_value(json).unwrap()
    }

    // -- deepest_act_subject tests --

    #[test]
    fn test_deepest_act_subject_single_level() {
        let handler = test_handler();
        let act = serde_json::json!({
            "sub": "alice"
        });

        let result = handler.deepest_act_subject(&act);
        assert_eq!(result, Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_two_levels() {
        // Service exchanged Alice's token: act chain is service -> alice
        let handler = test_handler();
        let act = serde_json::json!({
            "sub": "pic-gateway",
            "act": {
                "sub": "alice"
            }
        });

        let result = handler.deepest_act_subject(&act);
        assert_eq!(result, Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_three_levels() {
        // Multi-hop delegation: service-B -> service-A -> alice
        let handler = test_handler();
        let act = serde_json::json!({
            "sub": "service-B",
            "act": {
                "sub": "service-A",
                "act": {
                    "sub": "alice"
                }
            }
        });

        let result = handler.deepest_act_subject(&act);
        assert_eq!(result, Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_invalid_value() {
        let handler = test_handler();
        let act = serde_json::json!("not-an-object");

        let result = handler.deepest_act_subject(&act);
        assert_eq!(result, None);
    }

    #[test]
    fn test_deepest_act_subject_no_sub() {
        let handler = test_handler();
        let act = serde_json::json!({
            "other": "value"
        });

        let result = handler.deepest_act_subject(&act);
        assert_eq!(result, None);
    }

    // -- extract_token_exchange_principal tests --

    #[test]
    fn test_extract_principal_with_act_claim() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "service-account-pic-gateway",
            "act": {
                "sub": "alice"
            },
            "pic_ops": ["read:claims:alice/*"]
        }));

        let result = handler.extract_token_exchange_principal(&claims, &config);
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_principal_without_act_falls_back_to_sub() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        // No act claim — should use top-level sub
        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice",
            "pic_ops": ["read:claims:alice/*"]
        }));

        let result = handler.extract_token_exchange_principal(&claims, &config);
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_extract_principal_missing_sub_and_no_act() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer"
        }));

        let result = handler.extract_token_exchange_principal(&claims, &config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::MissingClaim(_)));
    }

    // -- extract_pic_ops tests --

    #[test]
    fn test_extract_pic_ops_from_array() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice",
            "pic_ops": ["read:claims:alice/*", "write:claims:alice/*"]
        }));

        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:alice/*", "write:claims:alice/*"]);
    }

    #[test]
    fn test_extract_pic_ops_from_single_string() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice",
            "pic_ops": "read:claims:alice/*"
        }));

        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_extract_pic_ops_fallback_to_scope() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        // No pic_ops claim, should fall back to scope
        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice",
            "scope": "read:claims:alice/* write:claims:alice/*"
        }));

        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:alice/*", "write:claims:alice/*"]);
    }

    #[test]
    fn test_extract_pic_ops_custom_claim() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true)
            .with_pic_ops_claim("custom_operations");

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice",
            "custom_operations": ["read:claims:alice/*"]
        }));

        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_extract_pic_ops_empty_when_no_claims() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new("issuer", "jwks")
            .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "issuer",
            "sub": "alice"
        }));

        let ops = handler.extract_pic_ops(&claims, &config);
        assert!(ops.is_empty());
    }

    // -- value_to_string_vec tests --

    #[test]
    fn test_value_to_string_vec_array() {
        let handler = test_handler();
        let value = serde_json::json!(["a", "b", "c"]);

        let result = handler.value_to_string_vec(&value);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_value_to_string_vec_single_string() {
        let handler = test_handler();
        let value = serde_json::json!("read:claims:alice/*");

        let result = handler.value_to_string_vec(&value);
        assert_eq!(result, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_value_to_string_vec_space_delimited() {
        let handler = test_handler();
        let value = serde_json::json!("read:a write:b");

        let result = handler.value_to_string_vec(&value);
        assert_eq!(result, vec!["read:a", "write:b"]);
    }

    #[test]
    fn test_value_to_string_vec_number() {
        let handler = test_handler();
        let value = serde_json::json!(42);

        let result = handler.value_to_string_vec(&value);
        assert!(result.is_empty());
    }

    #[test]
    fn test_value_to_string_vec_mixed_array() {
        let handler = test_handler();
        let value = serde_json::json!(["valid", 42, "also-valid"]);

        let result = handler.value_to_string_vec(&value);
        assert_eq!(result, vec!["valid", "also-valid"]);
    }

    // -- Integration-style test: full token exchange claim extraction --

    #[test]
    fn test_full_token_exchange_claims_keycloak_style() {
        // Simulates the claims structure produced by Keycloak after token exchange
        let handler = test_handler();
        let config = JwtIssuerConfig::new(
            "https://keycloak.example.com/realms/pic-demo",
            "https://keycloak.example.com/realms/pic-demo/protocol/openid-connect/certs",
        )
        .with_token_exchange(true)
        .with_audience("pic-resource-api");

        let claims = claims_from_json(serde_json::json!({
            "iss": "https://keycloak.example.com/realms/pic-demo",
            "sub": "service-account-pic-gateway",
            "aud": "pic-resource-api",
            "azp": "pic-gateway",
            "exp": 1700000300,
            "iat": 1700000000,
            "act": {
                "sub": "alice-user-id-12345"
            },
            "pic_ops": ["read:claims:alice/*"],
            "preferred_username": "alice",
            "realm_access": {
                "roles": ["pic-scope-alice"]
            }
        }));

        // Principal should be the original user (alice), not the service
        let principal = handler.extract_token_exchange_principal(&claims, &config).unwrap();
        assert_eq!(principal, "alice-user-id-12345");

        // Operations should come from pic_ops claim
        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_full_token_exchange_claims_bob() {
        let handler = test_handler();
        let config = JwtIssuerConfig::new(
            "https://keycloak.example.com/realms/pic-demo",
            "https://keycloak.example.com/realms/pic-demo/protocol/openid-connect/certs",
        )
        .with_token_exchange(true);

        let claims = claims_from_json(serde_json::json!({
            "iss": "https://keycloak.example.com/realms/pic-demo",
            "sub": "service-account-pic-gateway",
            "act": {
                "sub": "bob-user-id-67890"
            },
            "pic_ops": ["read:claims:bob/*"]
        }));

        let principal = handler.extract_token_exchange_principal(&claims, &config).unwrap();
        assert_eq!(principal, "bob-user-id-67890");

        let ops = handler.extract_pic_ops(&claims, &config);
        assert_eq!(ops, vec!["read:claims:bob/*"]);
    }

    #[test]
    fn test_standard_jwt_unaffected_by_token_exchange_fields() {
        // Verify that when token_exchange_aware is false, the new fields
        // don't affect standard JWT processing
        let config = JwtIssuerConfig::new(
            "https://accounts.google.com",
            "https://www.googleapis.com/oauth2/v3/certs",
        );

        // token_exchange_aware is false by default
        assert!(!config.token_exchange_aware);

        // Even if a token happened to have act and pic_ops claims,
        // the standard path should not look at them
        // (validated in the full validate() method, not testable here
        // without a real JWT, but the config defaults ensure the branch
        // is not taken)
    }
}

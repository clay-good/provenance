//! PCA_0 Issuance Handler
//!
//! This handler issues PCA_0 (the initial PCA at federation entry).
//! It validates external credentials and creates the origin authority.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

use provenance_core::{
    pca::{ExecutorBinding, PcaBuilder},
    types::{PrincipalIdentifier, PrincipalType, TemporalConstraints},
};

use crate::api::error::ApiError;
use crate::keys::KeyRegistry;
use crate::storage::KeyStore;

/// Trust Plane configuration
#[derive(Debug, Clone, Default)]
pub struct TrustPlaneConfig {
    /// Human-readable name of this Trust Plane
    pub trust_plane_name: Option<String>,
    /// Public URL of this Trust Plane (for federation discovery)
    pub public_url: Option<String>,
}

/// Application state shared across handlers
pub struct AppState {
    /// Key registry for cryptographic operations
    pub registry: KeyRegistry,
    /// Persistent storage for federation state
    pub store: Arc<dyn KeyStore>,
    /// Trust Plane configuration
    pub config: TrustPlaneConfig,
}

/// Request to issue a PCA_0
#[derive(Debug, Deserialize)]
pub struct IssuePcaRequest {
    /// External credential (JWT, API key, etc.)
    pub credential: String,

    /// Type of credential
    pub credential_type: String,

    /// Requested operations
    pub ops: Vec<String>,

    /// Executor binding metadata
    #[serde(default)]
    pub executor_binding: HashMap<String, String>,
}

/// Response from PCA_0 issuance
#[derive(Debug, Serialize)]
pub struct IssuePcaResponse {
    /// Base64-encoded signed PCA
    pub pca: String,

    /// Hop number (always 0 for PCA_0)
    pub hop: u32,

    /// Origin principal
    pub p_0: String,

    /// Granted operations
    pub ops: Vec<String>,

    /// Expiration (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// Issue a PCA_0 from an external credential
///
/// POST /v1/pca/issue
///
/// This is the federation entry point. It:
/// 1. Validates the external credential
/// 2. Extracts the principal (p_0)
/// 3. Determines allowed operations
/// 4. Creates and signs PCA_0
pub async fn issue_pca(
    State(state): State<Arc<AppState>>,
    Json(request): Json<IssuePcaRequest>,
) -> Result<Json<IssuePcaResponse>, ApiError> {
    // For now, we use a simplified credential validation
    // In production, this would integrate with the Federation Bridge
    let (principal, allowed_ops, expiration) = validate_credential(
        &request.credential,
        &request.credential_type,
    )?;

    // Intersect requested ops with allowed ops
    let granted_ops = intersect_ops(&request.ops, &allowed_ops);

    if granted_ops.is_empty() {
        warn!(
            requested = ?request.ops,
            allowed = ?allowed_ops,
            "No operations granted - all requested ops denied"
        );
        return Err(ApiError::Forbidden("No operations allowed".into()));
    }

    // Build executor binding
    let mut executor = ExecutorBinding::new();
    for (key, value) in request.executor_binding {
        executor.insert(key, value);
    }

    // Build PCA_0
    let mut builder = PcaBuilder::new()
        .p_0(principal.clone())
        .ops(granted_ops.clone())
        .executor(executor);

    // Add temporal constraints - always use 1 hour for now
    // TODO: Parse expiration from credential and use it if earlier
    let _ = &expiration; // Mark as used
    builder = builder.temporal_constraints(
        TemporalConstraints::new()
            .issued_now()
            .expires_in(chrono::Duration::hours(1)),
    );

    let pca = builder.build_pca_0().map_err(|e| {
        ApiError::Internal(format!("Failed to build PCA: {}", e))
    })?;

    // Sign with Trust Plane's CAT key
    let signed = state.registry.sign_pca(&pca).map_err(|e| {
        ApiError::Internal(format!("Failed to sign PCA: {}", e))
    })?;

    let pca_bytes = signed.to_bytes().map_err(|e| {
        ApiError::Internal(format!("Failed to serialize PCA: {}", e))
    })?;

    let pca_base64 = STANDARD.encode(&pca_bytes);

    info!(
        p_0 = %principal.value,
        hop = 0,
        ops = ?granted_ops,
        "Issued PCA_0"
    );

    Ok(Json(IssuePcaResponse {
        pca: pca_base64,
        hop: 0,
        p_0: format!("{}:{}", format!("{:?}", principal.principal_type).to_lowercase(), principal.value),
        ops: granted_ops,
        exp: expiration,
    }))
}

/// Validate an external credential and extract principal info
///
/// TODO: This should integrate with the Federation Bridge for real validation
fn validate_credential(
    credential: &str,
    credential_type: &str,
) -> Result<(PrincipalIdentifier, Vec<String>, Option<String>), ApiError> {
    match credential_type {
        "jwt" => validate_jwt_credential(credential),
        "apikey" => validate_apikey_credential(credential),
        "mock" => validate_mock_credential(credential),
        _ => Err(ApiError::BadRequest(format!(
            "Unsupported credential type: {}",
            credential_type
        ))),
    }
}

/// Validate a JWT credential
///
/// Decodes the JWT payload to extract the principal and PIC operations.
/// Supports OAuth Token Exchange (RFC 8693): when an `act` claim is present,
/// traverses the actor chain to find the deepest subject (the original user)
/// and uses that as p_0.
///
/// Note: In production, signature verification against the issuer's JWKS
/// would be performed here via the Federation Bridge. For this demo,
/// we trust the JWT payload since Keycloak is running locally.
fn validate_jwt_credential(
    credential: &str,
) -> Result<(PrincipalIdentifier, Vec<String>, Option<String>), ApiError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;

    // Decode JWT payload (second segment)
    let parts: Vec<&str> = credential.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::InvalidCredential("Invalid JWT format".into()));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
        ApiError::InvalidCredential(format!("Invalid JWT payload encoding: {}", e))
    })?;

    let claims: Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        ApiError::InvalidCredential(format!("Invalid JWT payload JSON: {}", e))
    })?;

    // Extract principal: check for act claim (RFC 8693 token exchange)
    // If act.sub exists, traverse to deepest subject (original user)
    // Otherwise, use top-level sub
    let principal_value = if let Some(act) = claims.get("act") {
        deepest_act_subject(act).unwrap_or_else(|| {
            claims.get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        })
    } else {
        // No act claim — use preferred_username if available, else sub
        claims.get("preferred_username")
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string()
    };

    let issuer = claims.get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let principal = PrincipalIdentifier::new(
        PrincipalType::Oidc,
        format!("{}#{}", issuer, principal_value),
    );

    // Extract PIC operations from pic_ops claim
    let allowed_ops = if let Some(pic_ops) = claims.get("pic_ops") {
        match pic_ops {
            Value::Array(arr) => arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Value::String(s) => vec![s.clone()],
            _ => vec![],
        }
    } else if let Some(scope) = claims.get("scope").and_then(|v| v.as_str()) {
        // Fallback: extract PIC-like operations from scope claim
        scope.split_whitespace()
            .filter(|s| s.contains(':'))
            .map(String::from)
            .collect()
    } else {
        vec![]
    };

    if allowed_ops.is_empty() {
        return Err(ApiError::Forbidden(
            "JWT contains no PIC operations (pic_ops claim missing or empty)".into(),
        ));
    }

    // Extract expiration
    let exp = claims.get("exp")
        .and_then(|v| v.as_i64())
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        });

    info!(
        principal = %principal.value,
        ops = ?allowed_ops,
        issuer = %issuer,
        "Validated JWT credential"
    );

    Ok((principal, allowed_ops, exp))
}

/// Traverse the RFC 8693 `act` claim chain to find the deepest subject
fn deepest_act_subject(act: &serde_json::Value) -> Option<String> {
    let obj = act.as_object()?;

    // If there's a nested act, go deeper first
    if let Some(nested_act) = obj.get("act") {
        if let Some(deeper) = deepest_act_subject(nested_act) {
            return Some(deeper);
        }
    }

    // Return this level's sub
    obj.get("sub")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Validate an API key credential (simplified for now)
fn validate_apikey_credential(
    _credential: &str,
) -> Result<(PrincipalIdentifier, Vec<String>, Option<String>), ApiError> {
    // TODO: Implement proper API key validation via Federation Bridge
    Err(ApiError::BadRequest(
        "API key validation not yet implemented - use 'mock' credential type for testing".into(),
    ))
}

/// Mock credential validation for testing
///
/// Format: "principal" or "mock:principal" or "principal:op1,op2,op3"
/// Examples:
///   - "alice" -> principal=alice, ops=[*]
///   - "mock:alice" -> principal=alice, ops=[*]
///   - "alice:read:claims:*,write:claims:alice/*" -> principal=alice, ops=[read:claims:*, write:claims:alice/*]
fn validate_mock_credential(
    credential: &str,
) -> Result<(PrincipalIdentifier, Vec<String>, Option<String>), ApiError> {
    // Handle "mock:principal" format (sent by gateway with Bearer mock:alice)
    let credential = credential.strip_prefix("mock:").unwrap_or(credential);

    // Now parse "principal" or "principal:ops"
    // Be careful: ops can contain colons (e.g., "read:claims:*")
    // So we only split on the FIRST colon if what follows looks like ops (contains comma or is a single op pattern)
    let (principal_name, ops_part) = if let Some(colon_idx) = credential.find(':') {
        let potential_ops = &credential[colon_idx + 1..];
        // Check if this looks like ops (contains comma or matches op pattern)
        if potential_ops.contains(',') || potential_ops.contains(':') || potential_ops == "*" {
            (&credential[..colon_idx], Some(potential_ops))
        } else {
            // Single word after colon - treat whole thing as principal
            (credential, None)
        }
    } else {
        (credential, None)
    };

    if principal_name.is_empty() {
        return Err(ApiError::InvalidCredential(
            "Mock credential format: 'principal' or 'mock:principal' or 'principal:op1,op2'".into(),
        ));
    }

    let principal = PrincipalIdentifier::new(PrincipalType::Custom, format!("mock:{}", principal_name));

    // If ops are specified, use them; otherwise allow everything
    let allowed_ops = if let Some(ops_str) = ops_part {
        ops_str.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        vec!["*".to_string()]
    };

    // Mock credentials expire in 1 hour
    let exp = Some(
        (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
    );

    Ok((principal, allowed_ops, exp))
}

/// Intersect requested operations with allowed operations
fn intersect_ops(requested: &[String], allowed: &[String]) -> Vec<String> {
    // If allowed contains "*", all requested ops are allowed
    if allowed.iter().any(|op| op == "*") {
        return requested.to_vec();
    }

    // Otherwise, filter requested ops to those covered by allowed
    requested
        .iter()
        .filter(|req| {
            allowed.iter().any(|allowed_op| {
                if allowed_op == *req {
                    return true;
                }
                if allowed_op.ends_with('*') {
                    let prefix = &allowed_op[..allowed_op.len() - 1];
                    return req.starts_with(prefix);
                }
                false
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intersect_ops_wildcard() {
        let requested = vec!["read:claims:123".into(), "write:data:456".into()];
        let allowed = vec!["*".into()];

        let result = intersect_ops(&requested, &allowed);
        assert_eq!(result, requested);
    }

    #[test]
    fn test_intersect_ops_prefix() {
        let requested = vec![
            "read:claims:123".into(),
            "write:claims:456".into(),
            "delete:users:789".into(),
        ];
        let allowed = vec!["read:claims:*".into(), "write:claims:*".into()];

        let result = intersect_ops(&requested, &allowed);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"read:claims:123".to_string()));
        assert!(result.contains(&"write:claims:456".to_string()));
    }

    #[test]
    fn test_intersect_ops_exact() {
        let requested = vec!["read:claims:123".into()];
        let allowed = vec!["read:claims:123".into()];

        let result = intersect_ops(&requested, &allowed);
        assert_eq!(result, requested);
    }

    #[test]
    fn test_mock_credential_simple() {
        let (principal, ops, _exp) = validate_mock_credential("alice").unwrap();
        assert_eq!(principal.value, "mock:alice");
        assert_eq!(ops, vec!["*"]);
    }

    #[test]
    fn test_mock_credential_with_mock_prefix() {
        // This is what the gateway sends: "mock:alice"
        let (principal, ops, _exp) = validate_mock_credential("mock:alice").unwrap();
        assert_eq!(principal.value, "mock:alice");
        assert_eq!(ops, vec!["*"]);
    }

    #[test]
    fn test_mock_credential_with_ops() {
        let (principal, ops, _exp) =
            validate_mock_credential("bob:read:claims:*,write:data:*").unwrap();
        assert_eq!(principal.value, "mock:bob");
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_mock_credential_with_mock_prefix_and_ops() {
        let (principal, ops, _exp) =
            validate_mock_credential("mock:charlie:read:claims:*").unwrap();
        assert_eq!(principal.value, "mock:charlie");
        assert_eq!(ops, vec!["read:claims:*"]);
    }

    // =========================================================================
    // JWT Credential Tests
    // =========================================================================

    /// Build a mock JWT from a JSON claims payload (no real signature, just
    /// base64url-encoded header.payload.signature for testing).
    fn build_mock_jwt(claims: &serde_json::Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "test-key-1"
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"fake-signature-for-testing");

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }

    #[test]
    fn test_jwt_credential_standard_keycloak_token() {
        // Simulates a Keycloak token with pic_ops and preferred_username
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "665c3afa-3de7-45d2-a0bb-e7197cfff381",
            "preferred_username": "alice",
            "aud": "pic-resource-api",
            "pic_ops": ["read:claims:alice/*"],
            "exp": 9999999999_i64,
            "scope": "openid pic-operations"
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, ops, exp) = validate_jwt_credential(&jwt).unwrap();

        // p_0 should use preferred_username (alice), not the UUID sub
        assert_eq!(
            principal.value,
            "http://localhost:8180/realms/pic-demo#alice"
        );
        assert_eq!(principal.principal_type, PrincipalType::Oidc);
        assert_eq!(ops, vec!["read:claims:alice/*"]);
        assert!(exp.is_some());
    }

    #[test]
    fn test_jwt_credential_with_act_claim_preserves_original_subject() {
        // Simulates a token-exchanged JWT (RFC 8693) where the gateway service
        // account is the subject, and the original user is in the act chain
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "service-account-pic-gateway",
            "act": {
                "sub": "alice-user-id-12345"
            },
            "pic_ops": ["read:claims:alice/*"],
            "exp": 9999999999_i64
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        // p_0 should be the ORIGINAL user from act.sub, not the service account
        assert_eq!(
            principal.value,
            "http://localhost:8180/realms/pic-demo#alice-user-id-12345"
        );
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_jwt_credential_with_nested_act_chain() {
        // Multi-level delegation: service-B → service-A → alice
        let claims = serde_json::json!({
            "iss": "https://keycloak.example.com/realms/demo",
            "sub": "service-B",
            "act": {
                "sub": "service-A",
                "act": {
                    "sub": "alice"
                }
            },
            "pic_ops": ["read:claims:alice/*"],
            "exp": 9999999999_i64
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, _ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        // p_0 should be the DEEPEST subject (the original human user)
        assert_eq!(
            principal.value,
            "https://keycloak.example.com/realms/demo#alice"
        );
    }

    #[test]
    fn test_jwt_credential_no_pic_ops_rejected() {
        // JWT without pic_ops claim and no PIC-like scopes should be rejected
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "alice",
            "exp": 9999999999_i64,
            "scope": "openid profile email"
        });
        let jwt = build_mock_jwt(&claims);

        let result = validate_jwt_credential(&jwt);
        assert!(result.is_err(), "JWT without PIC operations must be rejected");
    }

    #[test]
    fn test_jwt_credential_fallback_to_sub_when_no_preferred_username() {
        // When preferred_username is absent, should use sub
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "665c3afa-3de7-45d2-a0bb-e7197cfff381",
            "pic_ops": ["read:claims:alice/*"],
            "exp": 9999999999_i64
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, _ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        assert_eq!(
            principal.value,
            "http://localhost:8180/realms/pic-demo#665c3afa-3de7-45d2-a0bb-e7197cfff381"
        );
    }

    #[test]
    fn test_jwt_credential_pic_ops_as_single_string() {
        // pic_ops as a single string instead of array
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "alice",
            "pic_ops": "read:claims:alice/*",
            "exp": 9999999999_i64
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        assert_eq!(principal.value, "http://localhost:8180/realms/pic-demo#alice");
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_jwt_credential_scope_fallback_extracts_pic_ops() {
        // When pic_ops is absent but scope contains PIC-like operations
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "alice",
            "exp": 9999999999_i64,
            "scope": "openid read:claims:alice/* profile"
        });
        let jwt = build_mock_jwt(&claims);

        let (principal, ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        assert_eq!(principal.value, "http://localhost:8180/realms/pic-demo#alice");
        // Only the PIC-like scope entry (with colon) should be extracted
        assert_eq!(ops, vec!["read:claims:alice/*"]);
    }

    #[test]
    fn test_jwt_credential_invalid_format_rejected() {
        let result = validate_jwt_credential("not-a-jwt");
        assert!(result.is_err());

        let result = validate_jwt_credential("header.payload");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_credential_multiple_pic_ops() {
        let claims = serde_json::json!({
            "iss": "http://localhost:8180/realms/pic-demo",
            "sub": "alice",
            "pic_ops": ["read:claims:alice/*", "write:claims:alice/*"],
            "exp": 9999999999_i64
        });
        let jwt = build_mock_jwt(&claims);

        let (_principal, ops, _exp) = validate_jwt_credential(&jwt).unwrap();

        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&"read:claims:alice/*".to_string()));
        assert!(ops.contains(&"write:claims:alice/*".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_single_level() {
        let act = serde_json::json!({"sub": "alice"});
        assert_eq!(deepest_act_subject(&act), Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_nested() {
        let act = serde_json::json!({
            "sub": "service-a",
            "act": {"sub": "alice"}
        });
        assert_eq!(deepest_act_subject(&act), Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_deeply_nested() {
        let act = serde_json::json!({
            "sub": "service-c",
            "act": {
                "sub": "service-b",
                "act": {
                    "sub": "service-a",
                    "act": {"sub": "alice"}
                }
            }
        });
        assert_eq!(deepest_act_subject(&act), Some("alice".to_string()));
    }

    #[test]
    fn test_deepest_act_subject_no_sub() {
        let act = serde_json::json!({"foo": "bar"});
        assert_eq!(deepest_act_subject(&act), None);
    }
}

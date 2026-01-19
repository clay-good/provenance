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

/// Validate a JWT credential (simplified for now)
fn validate_jwt_credential(
    _credential: &str,
) -> Result<(PrincipalIdentifier, Vec<String>, Option<String>), ApiError> {
    // TODO: Implement proper JWT validation via Federation Bridge
    // For now, we reject JWT credentials as not yet implemented
    Err(ApiError::BadRequest(
        "JWT validation not yet implemented - use 'mock' credential type for testing".into(),
    ))
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
    let credential = if credential.starts_with("mock:") {
        &credential[5..]
    } else {
        credential
    };

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
}

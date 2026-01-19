//! Federation API Handlers
//!
//! Endpoints for Trust Plane federation:
//! - Register/discover federated Trust Planes (CATs)
//! - Cross-CAT authority verification
//! - Federation health and status

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::api::error::ApiError;
use crate::api::handlers::issue::AppState;

// =============================================================================
// Federation Discovery
// =============================================================================

/// Information about this Trust Plane for discovery
#[derive(Debug, Serialize)]
pub struct TrustPlaneInfo {
    /// Key ID of this Trust Plane's CAT
    pub kid: String,
    /// Base64-encoded public key
    pub public_key: String,
    /// Human-readable name
    pub name: Option<String>,
    /// API version
    pub api_version: String,
    /// Supported features
    pub features: Vec<String>,
}

/// GET /v1/federation/info
///
/// Returns information about this Trust Plane for discovery.
/// Other Trust Planes can use this to register us as a federated CAT.
pub async fn get_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<TrustPlaneInfo>, ApiError> {
    let kid = state.registry.cat_kid().to_string();
    let public_key = state.registry.cat_public_key();
    let public_key_base64 = STANDARD.encode(public_key.to_bytes());

    Ok(Json(TrustPlaneInfo {
        kid,
        public_key: public_key_base64,
        name: state.config.trust_plane_name.clone(),
        api_version: "v1".to_string(),
        features: vec![
            "pca_issuance".to_string(),
            "poc_processing".to_string(),
            "federation".to_string(),
            "revocation".to_string(),
        ],
    }))
}

// =============================================================================
// CAT Registration
// =============================================================================

/// Request to register a federated CAT
#[derive(Debug, Deserialize)]
pub struct RegisterCatRequest {
    /// Key ID of the CAT to register
    pub kid: String,
    /// Base64-encoded public key (32 bytes Ed25519)
    pub public_key: String,
    /// Human-readable name of the Trust Plane
    pub name: Option<String>,
    /// Endpoint URL for the Trust Plane
    pub endpoint: Option<String>,
}

/// Response from CAT registration
#[derive(Debug, Serialize)]
pub struct RegisterCatResponse {
    /// Whether registration was successful
    pub registered: bool,
    /// Key ID
    pub kid: String,
    /// Message
    pub message: String,
}

/// POST /v1/federation/cats
///
/// Register a federated Trust Plane's CAT public key.
/// This allows verifying PCAs signed by that Trust Plane.
pub async fn register_cat(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterCatRequest>,
) -> Result<Json<RegisterCatResponse>, ApiError> {
    // Decode public key
    let public_key_bytes = STANDARD.decode(&request.public_key)?;
    if public_key_bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!(
            "Invalid public key length: {}, expected 32",
            public_key_bytes.len()
        )));
    }

    // Register with storage
    let cat_info = crate::storage::CatInfo {
        kid: request.kid.clone(),
        public_key: public_key_bytes,
        name: request.name.clone(),
        endpoint: request.endpoint.clone(),
        registered_at: chrono::Utc::now(),
        is_local: false,
    };

    state.store.register_cat(cat_info).await.map_err(|e| {
        ApiError::Internal(format!("Failed to register CAT: {}", e))
    })?;

    // Also register with in-memory registry for immediate use
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&STANDARD.decode(&request.public_key)?);
    let public_key = provenance_core::crypto::PublicKey::from_bytes(&request.kid, &key_bytes)
        .map_err(|e| ApiError::BadRequest(format!("Invalid public key: {}", e)))?;

    state.registry.register_cat(request.kid.clone(), public_key);

    info!(
        kid = %request.kid,
        name = ?request.name,
        endpoint = ?request.endpoint,
        "Registered federated CAT"
    );

    Ok(Json(RegisterCatResponse {
        registered: true,
        kid: request.kid,
        message: "CAT registered successfully".to_string(),
    }))
}

/// Response listing federated CATs
#[derive(Debug, Serialize)]
pub struct ListCatsResponse {
    /// This Trust Plane's CAT
    pub local: CatEntry,
    /// Federated Trust Planes
    pub federated: Vec<CatEntry>,
}

/// CAT entry in listing
#[derive(Debug, Serialize)]
pub struct CatEntry {
    pub kid: String,
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub registered_at: String,
}

/// GET /v1/federation/cats
///
/// List all registered CATs (local and federated).
pub async fn list_cats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListCatsResponse>, ApiError> {
    let local_kid = state.registry.cat_kid().to_string();

    // Get local CAT info
    let local = CatEntry {
        kid: local_kid.clone(),
        name: state.config.trust_plane_name.clone(),
        endpoint: None, // Local doesn't have an endpoint
        registered_at: chrono::Utc::now().to_rfc3339(), // Approximation
    };

    // Get federated CATs
    let federated_cats = state.store.list_federated_cats().await.map_err(|e| {
        ApiError::Internal(format!("Failed to list CATs: {}", e))
    })?;

    let federated: Vec<CatEntry> = federated_cats
        .into_iter()
        .map(|c| CatEntry {
            kid: c.kid,
            name: c.name,
            endpoint: c.endpoint,
            registered_at: c.registered_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListCatsResponse { local, federated }))
}

/// DELETE /v1/federation/cats/:kid
///
/// Unregister a federated CAT.
pub async fn unregister_cat(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(kid): axum::extract::Path<String>,
) -> Result<Json<RegisterCatResponse>, ApiError> {
    // Can't unregister local CAT
    if kid == state.registry.cat_kid() {
        return Err(ApiError::BadRequest("Cannot unregister local CAT".into()));
    }

    let removed = state.store.unregister_cat(&kid).await.map_err(|e| {
        ApiError::Internal(format!("Failed to unregister CAT: {}", e))
    })?;

    if removed {
        info!(kid = %kid, "Unregistered federated CAT");
        Ok(Json(RegisterCatResponse {
            registered: false,
            kid,
            message: "CAT unregistered successfully".to_string(),
        }))
    } else {
        Err(ApiError::NotFound(format!("CAT not found: {}", kid)))
    }
}

// =============================================================================
// Federation Verification
// =============================================================================

/// Request to verify a PCA from a federated Trust Plane
#[derive(Debug, Deserialize)]
pub struct VerifyFederatedPcaRequest {
    /// Base64-encoded signed PCA
    pub pca: String,
}

/// Response from federated PCA verification
#[derive(Debug, Serialize)]
pub struct VerifyFederatedPcaResponse {
    /// Whether the PCA is valid
    pub valid: bool,
    /// Issuer CAT key ID
    pub issuer_kid: Option<String>,
    /// Whether the issuer is known
    pub issuer_known: bool,
    /// Origin principal
    pub p_0: Option<String>,
    /// Hop number
    pub hop: Option<u32>,
    /// Operations
    pub ops: Option<Vec<String>>,
    /// Error message if invalid
    pub error: Option<String>,
}

/// POST /v1/federation/verify
///
/// Verify a PCA signed by any known Trust Plane (local or federated).
/// This is used for cross-CAT authority verification.
pub async fn verify_federated_pca(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyFederatedPcaRequest>,
) -> Result<Json<VerifyFederatedPcaResponse>, ApiError> {
    use provenance_core::crypto::SignedPca;

    // Decode PCA
    let pca_bytes = STANDARD.decode(&request.pca)?;

    // Parse as SignedPca
    let signed_pca = match SignedPca::from_bytes(&pca_bytes) {
        Ok(pca) => pca,
        Err(e) => {
            return Ok(Json(VerifyFederatedPcaResponse {
                valid: false,
                issuer_kid: None,
                issuer_known: false,
                p_0: None,
                hop: None,
                ops: None,
                error: Some(format!("Invalid PCA format: {}", e)),
            }));
        }
    };

    // Extract issuer KID
    let issuer_kid = match signed_pca.kid() {
        Some(kid) => kid,
        None => {
            return Ok(Json(VerifyFederatedPcaResponse {
                valid: false,
                issuer_kid: None,
                issuer_known: false,
                p_0: None,
                hop: None,
                ops: None,
                error: Some("PCA missing issuer key ID".to_string()),
            }));
        }
    };

    // Look up issuer's public key
    let issuer_key = state.registry.get_cat(&issuer_kid);
    let issuer_known = issuer_key.is_some();

    if !issuer_known {
        warn!(kid = %issuer_kid, "Unknown CAT in PCA verification");
        return Ok(Json(VerifyFederatedPcaResponse {
            valid: false,
            issuer_kid: Some(issuer_kid.clone()),
            issuer_known: false,
            p_0: None,
            hop: None,
            ops: None,
            error: Some(format!("Unknown issuer: {}", issuer_kid)),
        }));
    }

    // Verify signature
    let issuer_key = issuer_key.unwrap();
    match issuer_key.verify_pca(&signed_pca) {
        Ok(pca) => {
            info!(
                kid = %issuer_kid,
                p_0 = %pca.p_0.value,
                hop = pca.hop,
                "Verified federated PCA"
            );

            Ok(Json(VerifyFederatedPcaResponse {
                valid: true,
                issuer_kid: Some(issuer_kid.clone()),
                issuer_known: true,
                p_0: Some(format!("{}:{}", format!("{:?}", pca.p_0.principal_type).to_lowercase(), pca.p_0.value)),
                hop: Some(pca.hop),
                ops: Some(pca.ops),
                error: None,
            }))
        }
        Err(e) => {
            warn!(kid = %issuer_kid, error = %e, "PCA signature verification failed");
            Ok(Json(VerifyFederatedPcaResponse {
                valid: false,
                issuer_kid: Some(issuer_kid.clone()),
                issuer_known: true,
                p_0: None,
                hop: None,
                ops: None,
                error: Some(format!("Signature verification failed: {}", e)),
            }))
        }
    }
}

// =============================================================================
// Auto-Discovery
// =============================================================================

/// Request to discover and register a Trust Plane by URL
#[derive(Debug, Deserialize)]
pub struct DiscoverCatRequest {
    /// URL of the Trust Plane to discover
    pub url: String,
}

/// POST /v1/federation/discover
///
/// Discover and register a Trust Plane by fetching its info endpoint.
/// This automates the federation handshake.
///
/// Note: Requires the `federation` feature for HTTP client support.
#[cfg(feature = "federation")]
pub async fn discover_cat(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DiscoverCatRequest>,
) -> Result<Json<RegisterCatResponse>, ApiError> {
    // Fetch the Trust Plane's info
    let info_url = format!("{}/v1/federation/info", request.url.trim_end_matches('/'));

    let client = reqwest::Client::new();
    let response = client
        .get(&info_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Failed to connect to {}: {}", info_url, e)))?;

    if !response.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "Trust Plane returned error: {}",
            response.status()
        )));
    }

    let info: TrustPlaneInfo = response
        .json()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Invalid response from Trust Plane: {}", e)))?;

    // Register the CAT
    let register_request = RegisterCatRequest {
        kid: info.kid.clone(),
        public_key: info.public_key,
        name: info.name,
        endpoint: Some(request.url),
    };

    register_cat(State(state), Json(register_request)).await
}

/// POST /v1/federation/discover (stub when federation feature is disabled)
#[cfg(not(feature = "federation"))]
pub async fn discover_cat(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<DiscoverCatRequest>,
) -> Result<Json<RegisterCatResponse>, ApiError> {
    Err(ApiError::BadRequest(
        "Auto-discovery requires the 'federation' feature. Use manual CAT registration instead.".into()
    ))
}

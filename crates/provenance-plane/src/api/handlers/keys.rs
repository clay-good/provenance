//! Executor Key Management Handlers
//!
//! Handles registration and listing of executor public keys.

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use provenance_core::crypto::PublicKey;

use crate::api::error::ApiError;
use crate::api::handlers::issue::AppState;

/// Request to register an executor's public key
#[derive(Debug, Deserialize)]
pub struct RegisterExecutorRequest {
    /// Key identifier (unique name for this key)
    pub kid: String,

    /// Base64-encoded Ed25519 public key (32 bytes)
    pub public_key: String,
}

/// Response from executor registration
#[derive(Debug, Serialize)]
pub struct RegisterExecutorResponse {
    /// Registered key ID
    pub kid: String,

    /// Success message
    pub message: String,
}

/// Request to list executor keys
#[derive(Debug, Serialize)]
pub struct ListExecutorsResponse {
    /// List of registered executor key IDs
    pub executors: Vec<String>,

    /// Total count
    pub count: usize,
}

/// Register an executor's public key
///
/// POST /v1/keys/executor
///
/// Executors must register their public keys before they can submit PoCs.
pub async fn register_executor(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterExecutorRequest>,
) -> Result<Json<RegisterExecutorResponse>, ApiError> {
    // Validate key ID
    if request.kid.is_empty() {
        return Err(ApiError::BadRequest("Key ID cannot be empty".into()));
    }

    if request.kid.len() > 256 {
        return Err(ApiError::BadRequest("Key ID too long (max 256 chars)".into()));
    }

    // Decode the public key
    let key_bytes = STANDARD.decode(&request.public_key).map_err(|e| {
        ApiError::BadRequest(format!("Invalid base64 encoding: {}", e))
    })?;

    // Validate key length (Ed25519 public keys are 32 bytes)
    if key_bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!(
            "Invalid key length: expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }

    let key_bytes: [u8; 32] = key_bytes.try_into().unwrap();

    // Create PublicKey
    let public_key = PublicKey::from_bytes(&request.kid, &key_bytes).map_err(|e| {
        ApiError::BadRequest(format!("Invalid public key: {}", e))
    })?;

    // Check if already registered
    if state.registry.has_executor(&request.kid) {
        info!(kid = %request.kid, "Updating existing executor key");
    } else {
        info!(kid = %request.kid, "Registering new executor key");
    }

    // Register the key
    state.registry.register_executor(request.kid.clone(), public_key);

    Ok(Json(RegisterExecutorResponse {
        kid: request.kid,
        message: "Executor key registered successfully".into(),
    }))
}

/// List registered executor key IDs
///
/// GET /v1/keys/executor
pub async fn list_executors(
    State(state): State<Arc<AppState>>,
) -> Json<ListExecutorsResponse> {
    let executors = state.registry.list_executor_kids();
    let count = executors.len();

    Json(ListExecutorsResponse { executors, count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenance_core::crypto::KeyPair;

    #[test]
    fn test_valid_key_encoding() {
        let kp = KeyPair::generate("test");
        let pk_bytes = kp.verifying_key_bytes();
        let encoded = STANDARD.encode(pk_bytes);

        // Verify we can decode it back
        let decoded = STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}

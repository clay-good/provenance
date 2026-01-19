//! PoC Processing Handler
//!
//! THIS IS THE HEART OF THE TRUST PLANE.
//!
//! This handler processes Proof of Continuity (PoC) requests and issues
//! successor PCAs. It enforces the three PIC invariants:
//!
//! 1. PROVENANCE: p_0 is copied from predecessor (never from request)
//! 2. IDENTITY: ops can only shrink (successor ⊆ predecessor)
//! 3. CONTINUITY: Cryptographic chain linking each hop

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use provenance_core::{
    crypto::{SignedPca, SignedPoc},
    pca::{ExecutorBinding, PcaBuilder, Provenance},
    types::Constraints,
};

use crate::api::error::ApiError;
use crate::api::handlers::issue::AppState;
use crate::core::{validate_monotonicity, validate_temporal};

/// Request to process a PoC
#[derive(Debug, Deserialize)]
pub struct ProcessPocRequest {
    /// Base64-encoded signed PoC
    pub poc: String,
}

/// Response from PoC processing
#[derive(Debug, Serialize)]
pub struct ProcessPocResponse {
    /// Base64-encoded signed successor PCA
    pub pca: String,

    /// Hop number
    pub hop: u32,

    /// Origin principal (unchanged from predecessor)
    pub p_0: String,

    /// Granted operations
    pub ops: Vec<String>,

    /// Expiration (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// Process a PoC and issue a successor PCA
///
/// POST /v1/poc/process
///
/// This is the CRITICAL path that enforces the PIC invariants.
/// The handler flow is:
///
/// 1. Parse and decode PoC
/// 2. Verify PoC signature (executor must be registered)
/// 3. Extract and verify predecessor PCA
/// 4. Validate temporal constraints
/// 5. ENFORCE MONOTONICITY (ops_{i+1} ⊆ ops_i)
/// 6. Build successor PCA with p_0 copied from predecessor
/// 7. Sign and return successor PCA
pub async fn process_poc(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessPocRequest>,
) -> Result<Json<ProcessPocResponse>, ApiError> {
    // Step 1: Base64-decode PoC bytes
    let poc_bytes = STANDARD.decode(&request.poc)?;

    // Step 2: Deserialize as SignedPoc
    let signed_poc = SignedPoc::from_bytes(&poc_bytes).map_err(|e| {
        ApiError::BadRequest(format!("Invalid PoC format: {}", e))
    })?;

    // Step 3: Extract executor kid from PoC signature
    let executor_kid = signed_poc.kid().ok_or_else(|| {
        ApiError::BadRequest("PoC missing executor key ID".into())
    })?;

    // Step 4: Look up executor's public key in registry
    let executor_key = state.registry.get_executor(&executor_kid).ok_or_else(|| {
        warn!(kid = %executor_kid, "Unknown executor attempted PoC");
        ApiError::UnknownExecutor(executor_kid.clone())
    })?;

    // Step 5: VERIFY PoC signature
    let poc = executor_key.verify_poc(&signed_poc).map_err(|e| {
        warn!(kid = %executor_kid, error = %e, "PoC signature verification failed");
        ApiError::InvalidSignature(format!("PoC signature invalid: {}", e))
    })?;

    // Step 6: Extract predecessor PCA bytes from PoC
    let predecessor_bytes = &poc.predecessor;

    // Step 7: Deserialize predecessor as SignedPca
    let signed_predecessor = SignedPca::from_bytes(predecessor_bytes).map_err(|e| {
        ApiError::BadRequest(format!("Invalid predecessor PCA format: {}", e))
    })?;

    // Step 8: Extract CAT kid from predecessor signature
    let cat_kid = signed_predecessor.kid().ok_or_else(|| {
        ApiError::BadRequest("Predecessor PCA missing CAT key ID".into())
    })?;

    // Step 9: Look up CAT's public key in registry
    let cat_key = state.registry.get_cat(&cat_kid).ok_or_else(|| {
        warn!(kid = %cat_kid, "Unknown CAT in predecessor PCA");
        ApiError::UnknownCat(cat_kid.clone())
    })?;

    // Step 10: VERIFY predecessor PCA signature
    let predecessor_pca = cat_key.verify_pca(&signed_predecessor).map_err(|e| {
        warn!(kid = %cat_kid, error = %e, "Predecessor PCA signature verification failed");
        ApiError::InvalidSignature(format!("Predecessor PCA signature invalid: {}", e))
    })?;

    // Step 11: VALIDATE temporal constraints
    validate_temporal(&predecessor_pca)?;

    // =========================================================================
    // NOW ENFORCE THE THREE INVARIANTS
    // =========================================================================

    // Step 12: MONOTONICITY CHECK
    // This is the CRITICAL check that prevents confused deputy attacks
    let successor_ops = &poc.successor.ops;
    validate_monotonicity(&predecessor_pca.ops, successor_ops)?;

    info!(
        predecessor_hop = predecessor_pca.hop,
        predecessor_ops = ?predecessor_pca.ops,
        successor_ops = ?successor_ops,
        "Monotonicity check passed"
    );

    // Step 13: Build successor PCA
    // CRITICAL: p_0 is ALWAYS copied from predecessor, never from request
    let provenance = Provenance {
        cat_kid: cat_kid.clone(),
        cat_sig: signed_predecessor.signature().to_vec(),
        executor_kid: executor_kid.clone(),
        executor_sig: signed_poc.signature().to_vec(),
    };

    let executor_binding = poc.successor.executor.unwrap_or_else(ExecutorBinding::new);
    let constraints = merge_constraints(
        predecessor_pca.constraints.as_ref(),
        poc.successor.constraints.as_ref(),
    );

    let mut builder = PcaBuilder::new()
        .ops(successor_ops.clone())
        .executor(executor_binding);

    if let Some(ref c) = constraints {
        builder = builder.constraints(c.clone());
    }

    let successor_pca = builder
        .build_successor(&predecessor_pca, provenance)
        .map_err(|e| ApiError::Internal(format!("Failed to build successor PCA: {}", e)))?;

    // Verify the invariants are satisfied in the built PCA
    debug_assert_eq!(successor_pca.p_0, predecessor_pca.p_0, "p_0 immutability violated!");
    debug_assert_eq!(successor_pca.hop, predecessor_pca.hop + 1, "hop increment violated!");

    // Step 14: Sign successor PCA with Trust Plane's CAT key
    let signed_successor = state.registry.sign_pca(&successor_pca).map_err(|e| {
        ApiError::Internal(format!("Failed to sign successor PCA: {}", e))
    })?;

    let successor_bytes = signed_successor.to_bytes().map_err(|e| {
        ApiError::Internal(format!("Failed to serialize successor PCA: {}", e))
    })?;

    let successor_base64 = STANDARD.encode(&successor_bytes);

    // Extract expiration for response
    let exp = constraints
        .as_ref()
        .and_then(|c| c.temporal.as_ref())
        .and_then(|t| t.exp.clone());

    info!(
        p_0 = %successor_pca.p_0.value,
        hop = successor_pca.hop,
        ops = ?successor_pca.ops,
        executor = %executor_kid,
        "Issued successor PCA"
    );

    Ok(Json(ProcessPocResponse {
        pca: successor_base64,
        hop: successor_pca.hop,
        p_0: format!(
            "{}:{}",
            format!("{:?}", successor_pca.p_0.principal_type).to_lowercase(),
            successor_pca.p_0.value
        ),
        ops: successor_pca.ops,
        exp,
    }))
}

/// Merge constraints from predecessor and requested
///
/// The merged constraints are the intersection (most restrictive):
/// - Expiration: earlier of the two
/// - Not-before: later of the two
/// - Budget: lower of the two
fn merge_constraints(
    predecessor: Option<&Constraints>,
    requested: Option<&Constraints>,
) -> Option<Constraints> {
    match (predecessor, requested) {
        (None, None) => None,
        (Some(p), None) => Some(p.clone()),
        (None, Some(r)) => Some(r.clone()),
        (Some(p), Some(r)) => {
            let mut merged = p.clone();

            // Merge temporal constraints
            if let (Some(ref mut pt), Some(ref rt)) = (&mut merged.temporal, &r.temporal) {
                // Use earlier expiration
                if let (Some(ref pexp), Some(ref rexp)) = (&pt.exp, &rt.exp) {
                    if rexp < pexp {
                        pt.exp = Some(rexp.clone());
                    }
                } else if rt.exp.is_some() {
                    pt.exp = rt.exp.clone();
                }

                // Use later not-before
                if let (Some(ref pnbf), Some(ref rnbf)) = (&pt.nbf, &rt.nbf) {
                    if rnbf > pnbf {
                        pt.nbf = Some(rnbf.clone());
                    }
                } else if rt.nbf.is_some() {
                    pt.nbf = rt.nbf.clone();
                }
            } else if r.temporal.is_some() {
                merged.temporal = r.temporal.clone();
            }

            // Merge budget constraints
            if let (Some(ref mut pb), Some(ref rb)) = (&mut merged.budget, &r.budget) {
                // Use lower max_cost
                if let (Some(pmax), Some(rmax)) = (pb.max_cost, rb.max_cost) {
                    pb.max_cost = Some(pmax.min(rmax));
                } else if rb.max_cost.is_some() {
                    pb.max_cost = rb.max_cost;
                }
            } else if r.budget.is_some() {
                merged.budget = r.budget.clone();
            }

            Some(merged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provenance_core::types::{BudgetConstraints, TemporalConstraints};

    #[test]
    fn test_merge_constraints_none() {
        assert!(merge_constraints(None, None).is_none());
    }

    #[test]
    fn test_merge_constraints_predecessor_only() {
        let pred = Constraints {
            temporal: Some(TemporalConstraints {
                exp: Some("2026-01-20T00:00:00Z".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = merge_constraints(Some(&pred), None);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().temporal.unwrap().exp,
            Some("2026-01-20T00:00:00Z".into())
        );
    }

    #[test]
    fn test_merge_constraints_earlier_expiration() {
        let pred = Constraints {
            temporal: Some(TemporalConstraints {
                exp: Some("2026-01-20T00:00:00Z".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let req = Constraints {
            temporal: Some(TemporalConstraints {
                exp: Some("2026-01-18T00:00:00Z".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = merge_constraints(Some(&pred), Some(&req)).unwrap();
        assert_eq!(
            result.temporal.unwrap().exp,
            Some("2026-01-18T00:00:00Z".into())
        );
    }

    #[test]
    fn test_merge_constraints_lower_budget() {
        let pred = Constraints {
            budget: Some(BudgetConstraints {
                max_cost: Some(100.0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let req = Constraints {
            budget: Some(BudgetConstraints {
                max_cost: Some(50.0),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = merge_constraints(Some(&pred), Some(&req)).unwrap();
        assert_eq!(result.budget.unwrap().max_cost, Some(50.0));
    }
}

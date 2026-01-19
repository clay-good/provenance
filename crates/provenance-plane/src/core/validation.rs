//! Validation logic for the Trust Plane
//!
//! This module contains the critical security validation functions that
//! enforce the three PIC invariants.

use provenance_core::pca::Pca;
use thiserror::Error;
use tracing::warn;

/// Error returned when monotonicity is violated
///
/// This is a SECURITY-CRITICAL error indicating an attempt to
/// escalate privileges beyond what the predecessor authorized.
#[derive(Error, Debug, Clone)]
#[error("Monotonicity violation: operations {violating_ops:?} not in predecessor ops {predecessor_ops:?}")]
pub struct MonotonicityError {
    /// Operations that violated monotonicity
    pub violating_ops: Vec<String>,
    /// Operations allowed by predecessor
    pub predecessor_ops: Vec<String>,
    /// Operations requested by successor
    pub successor_ops: Vec<String>,
}

/// Validate monotonicity: ensure successor ops ⊆ predecessor ops
///
/// This is the CRITICAL function that prevents confused deputy attacks.
/// Every successor operation MUST be authorized by the predecessor.
///
/// # Arguments
/// * `predecessor_ops` - Operations allowed by the predecessor PCA
/// * `successor_ops` - Operations requested for the successor PCA
///
/// # Returns
/// * `Ok(())` if all successor ops are covered by predecessor ops
/// * `Err(MonotonicityError)` if any successor op is not authorized
///
/// # Security
/// This function MUST be called before issuing any successor PCA.
/// Failure to call this function defeats the entire security model.
pub fn validate_monotonicity(
    predecessor_ops: &[String],
    successor_ops: &[String],
) -> Result<(), MonotonicityError> {
    let mut violations = Vec::new();

    for op in successor_ops {
        if !op_is_covered(op, predecessor_ops) {
            violations.push(op.clone());
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        // Log security-critical event
        warn!(
            violating_ops = ?violations,
            predecessor_ops = ?predecessor_ops,
            successor_ops = ?successor_ops,
            "SECURITY: Monotonicity violation detected"
        );

        Err(MonotonicityError {
            violating_ops: violations,
            predecessor_ops: predecessor_ops.to_vec(),
            successor_ops: successor_ops.to_vec(),
        })
    }
}

/// Check if an operation is covered by a set of predecessor operations
///
/// Supports wildcard matching:
/// - "*" covers everything
/// - "read:*" covers "read:claims:123"
/// - "read:claims:*" covers "read:claims:123"
fn op_is_covered(op: &str, predecessor_ops: &[String]) -> bool {
    for allowed in predecessor_ops {
        // Universal wildcard covers everything
        if allowed == "*" {
            return true;
        }

        // Exact match
        if allowed == op {
            return true;
        }

        // Wildcard prefix matching
        if allowed.ends_with('*') {
            let prefix = &allowed[..allowed.len() - 1];
            if op.starts_with(prefix) {
                return true;
            }
        }
    }

    false
}

/// Validate that a PCA's temporal constraints are satisfied
pub fn validate_temporal(pca: &Pca) -> Result<(), TemporalError> {
    pca.validate_temporal().map_err(|e| match e {
        provenance_core::ProvenanceError::PcaExpired(exp) => TemporalError::Expired(exp),
        provenance_core::ProvenanceError::PcaNotYetValid(nbf) => TemporalError::NotYetValid(nbf),
        _ => TemporalError::Other(e.to_string()),
    })
}

/// Error returned when temporal constraints are violated
#[derive(Error, Debug, Clone)]
pub enum TemporalError {
    #[error("PCA expired at {0}")]
    Expired(String),

    #[error("PCA not valid until {0}")]
    NotYetValid(String),

    #[error("Temporal validation error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonicity_exact_match() {
        let pred = vec!["read:claims:123".into()];
        let succ = vec!["read:claims:123".into()];

        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_monotonicity_subset() {
        let pred = vec!["read:claims:*".into(), "write:claims:*".into()];
        let succ = vec!["read:claims:123".into()];

        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_monotonicity_violation() {
        let pred = vec!["read:claims:alice/*".into()];
        let succ = vec!["read:claims:bob/*".into()];

        let result = validate_monotonicity(&pred, &succ);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.violating_ops.contains(&"read:claims:bob/*".to_string()));
    }

    #[test]
    fn test_monotonicity_universal_wildcard() {
        let pred = vec!["*".into()];
        let succ = vec!["read:anything".into(), "write:everything".into()];

        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_monotonicity_partial_violation() {
        let pred = vec!["read:claims:*".into()];
        let succ = vec!["read:claims:123".into(), "write:claims:123".into()];

        let result = validate_monotonicity(&pred, &succ);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.violating_ops.len(), 1);
        assert!(err.violating_ops.contains(&"write:claims:123".to_string()));
    }

    #[test]
    fn test_monotonicity_empty_successor() {
        let pred = vec!["read:claims:*".into()];
        let succ: Vec<String> = vec![];

        // Empty successor is always valid (requesting nothing)
        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_monotonicity_nested_wildcard() {
        let pred = vec!["read:claims:alice/*".into()];
        let succ = vec!["read:claims:alice/doc1".into(), "read:claims:alice/doc2".into()];

        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_monotonicity_action_prefix_wildcard() {
        let pred = vec!["read:*".into()];
        let succ = vec!["read:claims:123".into(), "read:users:456".into()];

        assert!(validate_monotonicity(&pred, &succ).is_ok());
    }

    #[test]
    fn test_op_coverage_scenarios() {
        // Exact match
        assert!(op_is_covered("read:claims:123", &["read:claims:123".into()]));

        // Wildcard suffix
        assert!(op_is_covered("read:claims:123", &["read:claims:*".into()]));
        assert!(op_is_covered("read:claims:alice/doc", &["read:claims:alice/*".into()]));

        // Universal wildcard
        assert!(op_is_covered("anything:here", &["*".into()]));

        // Not covered
        assert!(!op_is_covered("write:claims:123", &["read:claims:*".into()]));
        assert!(!op_is_covered("read:claims:bob/x", &["read:claims:alice/*".into()]));
    }
}

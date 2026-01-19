//! Integration Tests for Trust Plane
//!
//! These tests verify the Trust Plane API behavior:
//! - PCA_0 issuance from external credentials
//! - PoC processing and successor PCA generation
//! - Key registration and lookup
//! - Invariant enforcement at the API level

use provenance_core::{
    crypto::KeyPair,
    ExecutorBinding, OperationSet, Pca, PcaBuilder, PrincipalIdentifier,
    ProvenanceError, Provenance, TemporalConstraints,
};
use provenance_plane::KeyRegistry;

// =============================================================================
// Test Helpers
// =============================================================================

/// Create a mock PCA_0 for testing
fn create_mock_pca_0(principal: &str, ops: Vec<String>) -> Pca {
    PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc(principal))
        .ops(ops)
        .executor(ExecutorBinding::new().with("service", "test"))
        .build_pca_0()
        .expect("Failed to create mock PCA_0")
}

/// Create mock provenance for testing
fn create_mock_provenance(hop: u32) -> Provenance {
    Provenance {
        cat_kid: format!("trust-plane-{}", hop),
        cat_sig: vec![0xCA, 0x7E, hop as u8, 0x01, 0x02, 0x03],
        executor_kid: format!("executor-{}", hop),
        executor_sig: vec![0xEE, 0x1C, hop as u8, 0x04, 0x05, 0x06],
    }
}

// =============================================================================
// PCA Tests
// =============================================================================

#[test]
fn test_pca_0_creation_valid() {
    let pca = create_mock_pca_0("user:alice", vec!["read:*".into(), "write:data:*".into()]);

    assert!(pca.is_pca_0());
    assert_eq!(pca.hop, 0);
    assert!(pca.provenance.is_none());
    assert_eq!(pca.p_0.value, "user:alice");
    assert_eq!(pca.ops.len(), 2);
}

#[test]
fn test_successor_pca_creation() {
    let pca_0 = create_mock_pca_0("user:alice", vec!["read:*".into()]);

    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:data:123".into()])
        .executor(ExecutorBinding::new().with("service", "downstream"))
        .build_successor(&pca_0, create_mock_provenance(1))
        .expect("Should create successor");

    assert_eq!(pca_1.hop, 1);
    assert_eq!(pca_1.p_0, pca_0.p_0); // PROVENANCE invariant
    assert!(pca_1.provenance.is_some()); // CONTINUITY invariant
}

#[test]
fn test_p_0_immutability_enforced() {
    let pca_0 = create_mock_pca_0("user:alice", vec!["read:*".into()]);

    // Even if we try to set a different p_0, build_successor uses predecessor's
    let pca_1 = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:evil")) // This will be ignored
        .ops(vec!["read:data:123".into()])
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    // p_0 must be alice, not evil
    assert_eq!(pca_1.p_0.value, "user:alice");
}

#[test]
fn test_full_chain_three_hops() {
    // Hop 0: Full authority
    let pca_0 = create_mock_pca_0(
        "user:alice",
        vec![
            "read:*".into(),
            "write:archive:*".into(),
            "write:storage:*".into(),
        ],
    );

    // Hop 1: Narrow to archive operations
    let pca_1 = PcaBuilder::new()
        .ops(vec!["write:archive:*".into()])
        .executor(ExecutorBinding::new().with("service", "gateway"))
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    assert_eq!(pca_1.hop, 1);
    assert_eq!(pca_1.p_0, pca_0.p_0);

    // Hop 2: Narrow to storage operations
    let pca_2 = PcaBuilder::new()
        .ops(vec!["write:storage:*".into()])
        .executor(ExecutorBinding::new().with("service", "archive"))
        .build_successor(&pca_1, create_mock_provenance(2))
        .unwrap();

    assert_eq!(pca_2.hop, 2);
    assert_eq!(pca_2.p_0, pca_0.p_0); // Still alice after 2 hops
    assert!(pca_2.provenance.is_some());
}

// =============================================================================
// Operation Tests
// =============================================================================

#[test]
fn test_contains_op_exact_match() {
    let pca = create_mock_pca_0("user:alice", vec!["read:claims:123".into()]);

    assert!(pca.contains_op("read:claims:123"));
    assert!(!pca.contains_op("read:claims:456"));
    assert!(!pca.contains_op("write:claims:123"));
}

#[test]
fn test_contains_op_wildcard() {
    let pca = create_mock_pca_0("user:alice", vec!["read:claims:*".into()]);

    assert!(pca.contains_op("read:claims:123"));
    assert!(pca.contains_op("read:claims:456"));
    assert!(pca.contains_op("read:claims:alice/doc1"));
    assert!(!pca.contains_op("write:claims:123"));
    assert!(!pca.contains_op("read:data:123"));
}

#[test]
fn test_contains_op_global_wildcard() {
    let pca = create_mock_pca_0("user:admin", vec!["*".into()]);

    assert!(pca.contains_op("read:claims:123"));
    assert!(pca.contains_op("write:anything:anywhere"));
    assert!(pca.contains_op("delete:everything:now"));
}

// =============================================================================
// Monotonicity Tests
// =============================================================================

#[test]
fn test_operation_set_monotonicity() {
    let parent = OperationSet::from_strings(&["read:data:*", "write:data:*"]).unwrap();
    let valid_child = OperationSet::from_strings(&["read:data:123"]).unwrap();
    let invalid_child = OperationSet::from_strings(&["delete:data:123"]).unwrap();

    assert!(parent.validate_monotonicity(&valid_child).is_ok());
    assert!(parent.validate_monotonicity(&invalid_child).is_err());
}

#[test]
fn test_monotonicity_wildcard_narrows_to_specific() {
    let parent = OperationSet::from_strings(&["read:*"]).unwrap();
    let child = OperationSet::from_strings(&["read:claims:alice:doc1"]).unwrap();

    assert!(parent.validate_monotonicity(&child).is_ok());
}

#[test]
fn test_monotonicity_rejects_broadening() {
    let parent = OperationSet::from_strings(&["read:claims:alice:*"]).unwrap();
    let child = OperationSet::from_strings(&["read:claims:*"]).unwrap(); // Broader!

    assert!(parent.validate_monotonicity(&child).is_err());
}

// =============================================================================
// Serialization Tests
// =============================================================================

#[test]
fn test_pca_serialization_roundtrip() {
    let pca = create_mock_pca_0(
        "user:alice",
        vec!["read:claims:*".into(), "write:archive:*".into()],
    );

    let bytes = pca.to_bytes().expect("Serialization should succeed");
    let restored = Pca::from_bytes(&bytes).expect("Deserialization should succeed");

    assert_eq!(pca, restored);
}

#[test]
fn test_pca_with_provenance_serialization() {
    let pca_0 = create_mock_pca_0("user:alice", vec!["read:*".into()]);

    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:data:*".into()])
        .executor(
            ExecutorBinding::new()
                .with("service", "test")
                .with("agent_id", "agent-123"),
        )
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    let bytes = pca_1.to_bytes().unwrap();
    let restored = Pca::from_bytes(&bytes).unwrap();

    assert_eq!(pca_1.hop, restored.hop);
    assert_eq!(pca_1.p_0, restored.p_0);
    assert_eq!(pca_1.ops, restored.ops);
    assert!(restored.provenance.is_some());
}

// =============================================================================
// Temporal Constraint Tests
// =============================================================================

#[test]
fn test_temporal_constraints_valid() {
    use chrono::Duration;

    let pca = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:alice"))
        .ops(vec!["read:*".into()])
        .temporal_constraints(
            TemporalConstraints::new()
                .issued_now()
                .expires_in(Duration::hours(1)),
        )
        .build_pca_0()
        .unwrap();

    assert!(pca.validate_temporal().is_ok());
}

#[test]
fn test_temporal_constraints_expired() {
    use chrono::Duration;

    let pca = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:alice"))
        .ops(vec!["read:*".into()])
        .temporal_constraints(
            TemporalConstraints::new()
                .issued_now()
                .expires_in(Duration::hours(-1)), // Already expired
        )
        .build_pca_0()
        .unwrap();

    let result = pca.validate_temporal();
    assert!(result.is_err());
    assert!(matches!(result, Err(ProvenanceError::PcaExpired(_))));
}

// =============================================================================
// Key Registry Tests
// =============================================================================

#[test]
fn test_key_registry_creation() {
    let registry = KeyRegistry::generate("test-cat");

    assert_eq!(registry.cat_kid(), "test-cat");
    assert!(registry.has_cat("test-cat"));
}

#[test]
fn test_key_registry_executor_registration() {
    let registry = KeyRegistry::generate("test-cat");
    let executor_kp = KeyPair::generate("executor-1");

    registry.register_executor("executor-1".into(), executor_kp.public_key());

    assert!(registry.has_executor("executor-1"));
    assert!(!registry.has_executor("executor-2"));
    assert_eq!(registry.executor_count(), 1);
}

#[test]
fn test_key_registry_executor_lookup() {
    let registry = KeyRegistry::generate("test-cat");
    let executor_kp = KeyPair::generate("executor-1");

    registry.register_executor("executor-1".into(), executor_kp.public_key());

    // Lookup should succeed
    let found = registry.get_executor("executor-1");
    assert!(found.is_some());

    // Unknown key should return None
    assert!(registry.get_executor("unknown-key").is_none());
}

#[test]
fn test_key_registry_list_executors() {
    let registry = KeyRegistry::generate("test-cat");

    let kp1 = KeyPair::generate("exec-1");
    let kp2 = KeyPair::generate("exec-2");
    let kp3 = KeyPair::generate("exec-3");

    registry.register_executor("exec-1".into(), kp1.public_key());
    registry.register_executor("exec-2".into(), kp2.public_key());
    registry.register_executor("exec-3".into(), kp3.public_key());

    let keys = registry.list_executor_kids();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&"exec-1".to_string()));
    assert!(keys.contains(&"exec-2".to_string()));
    assert!(keys.contains(&"exec-3".to_string()));
}

#[test]
fn test_key_registry_unregister_executor() {
    let registry = KeyRegistry::generate("test-cat");
    let kp = KeyPair::generate("exec-1");

    registry.register_executor("exec-1".into(), kp.public_key());
    assert!(registry.has_executor("exec-1"));

    registry.unregister_executor("exec-1");
    assert!(!registry.has_executor("exec-1"));
}

#[test]
fn test_key_registry_sign_pca() {
    let registry = KeyRegistry::generate("test-cat");

    let pca = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:alice"))
        .ops(vec!["read:*".into()])
        .executor(ExecutorBinding::new().with("service", "gateway"))
        .build_pca_0()
        .unwrap();

    let signed = registry.sign_pca(&pca).unwrap();

    // Verify with our own CAT key
    let cat_key = registry.get_cat(registry.cat_kid()).unwrap();
    let verified = cat_key.verify_pca(&signed).unwrap();

    assert_eq!(verified, pca);
}

#[test]
fn test_key_registry_cat_federation() {
    let registry1 = KeyRegistry::generate("cat-1");
    let registry2 = KeyRegistry::generate("cat-2");

    // Register cat-2's public key in registry1
    registry1.register_cat("cat-2".into(), registry2.cat_public_key());

    assert!(registry1.has_cat("cat-2"));

    // Sign a PCA with cat-2
    let pca = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:bob"))
        .ops(vec!["write:*".into()])
        .build_pca_0()
        .unwrap();

    let signed = registry2.sign_pca(&pca).unwrap();

    // Verify with cat-2's key from registry1
    let cat2_key = registry1.get_cat("cat-2").unwrap();
    let verified = cat2_key.verify_pca(&signed).unwrap();

    assert_eq!(verified, pca);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_ops_allowed() {
    let pca = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:alice"))
        .ops(vec![]) // Empty ops
        .build_pca_0()
        .unwrap();

    assert!(pca.ops.is_empty());
    assert!(!pca.contains_op("anything"));
}

#[test]
fn test_executor_binding_with_many_fields() {
    let binding = ExecutorBinding::new()
        .with("service", "gateway")
        .with("agent_id", "agent-123")
        .with("tool", "get_claims")
        .with("task_id", "task-456")
        .with("federation", "example.com");

    assert_eq!(binding.len(), 5);
    assert_eq!(binding.get("service"), Some("gateway"));
    assert_eq!(binding.get("agent_id"), Some("agent-123"));
    assert_eq!(binding.get("tool"), Some("get_claims"));
    assert_eq!(binding.get("task_id"), Some("task-456"));
    assert_eq!(binding.get("federation"), Some("example.com"));
}

#[test]
fn test_long_chain_preserves_p_0() {
    let original_p_0 = PrincipalIdentifier::oidc("user:alice");
    let mut current = create_mock_pca_0("user:alice", vec!["*".into()]);

    // Create a chain of 50 hops
    for hop in 1..=50 {
        let successor = PcaBuilder::new()
            .ops(vec!["read:*".into()])
            .executor(ExecutorBinding::new().with("hop", hop.to_string()))
            .build_successor(&current, create_mock_provenance(hop))
            .unwrap();

        // p_0 must remain alice at every hop
        assert_eq!(successor.p_0, original_p_0);
        assert_eq!(successor.hop, hop);

        current = successor;
    }
}

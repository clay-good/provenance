//! Property-Based Tests for PIC Invariants
//!
//! These tests verify that the three PIC invariants hold for arbitrary inputs:
//! 1. PROVENANCE: p_0 is IMMUTABLE throughout the chain
//! 2. IDENTITY: ops can only SHRINK (ops_{i+1} ⊆ ops_i)
//! 3. CONTINUITY: Cryptographic chain links each hop
//!
//! Uses proptest for property-based testing with arbitrary inputs.

use proptest::prelude::*;
use provenance_core::{
    ExecutorBinding, OperationSet, Pca, PcaBuilder, PrincipalIdentifier, Provenance,
};

// =============================================================================
// INVARIANT 1: PROVENANCE - p_0 is IMMUTABLE
// =============================================================================

proptest! {
    /// Verify that p_0 remains unchanged across any number of hops
    #[test]
    fn prop_p_0_immutability_through_chain(
        principal in "[a-z]{3,10}",
        hops in 1..20u32,
    ) {
        let p_0 = PrincipalIdentifier::oidc(&format!("user:{}", principal));

        // Create PCA_0
        let pca_0 = PcaBuilder::new()
            .p_0(p_0.clone())
            .ops(vec!["*".into()])
            .build_pca_0()
            .expect("PCA_0 creation should succeed");

        // Simulate chain of hops
        let mut current = pca_0;
        for hop in 1..=hops {
            let provenance = create_mock_provenance(hop);

            let successor = PcaBuilder::new()
                .ops(vec!["read:data:*".into()])
                .executor(ExecutorBinding::new().with("hop", hop.to_string()))
                .build_successor(&current, provenance)
                .expect("Successor creation should succeed");

            // INVARIANT: p_0 must be identical to predecessor
            prop_assert_eq!(
                successor.p_0.clone(),
                current.p_0.clone(),
                "p_0 must be immutable: hop {} changed p_0",
                hop
            );

            // INVARIANT: p_0 must match the original
            prop_assert_eq!(
                successor.p_0.value.clone(),
                format!("user:{}", principal),
                "p_0 must match original principal at hop {}",
                hop
            );

            current = successor;
        }
    }

    /// Verify that build_successor ignores any p_0 set on the builder
    #[test]
    fn prop_build_successor_ignores_p_0_parameter(
        original_principal in "[a-z]{3,10}",
        attacker_principal in "[a-z]{3,10}",
    ) {
        prop_assume!(original_principal != attacker_principal);

        let original_p_0 = PrincipalIdentifier::oidc(&format!("user:{}", original_principal));
        let attacker_p_0 = PrincipalIdentifier::oidc(&format!("user:{}", attacker_principal));

        let pca_0 = PcaBuilder::new()
            .p_0(original_p_0.clone())
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        let provenance = create_mock_provenance(1);

        // Attacker tries to set a different p_0
        let pca_1 = PcaBuilder::new()
            .p_0(attacker_p_0) // This should be IGNORED
            .ops(vec!["read:data:*".into()])
            .build_successor(&pca_0, provenance)
            .unwrap();

        // INVARIANT: p_0 must be original, not attacker's
        prop_assert_eq!(
            pca_1.p_0,
            original_p_0,
            "build_successor must ignore p_0 parameter and use predecessor's"
        );
    }
}

// =============================================================================
// INVARIANT 2: IDENTITY - ops can only SHRINK
// =============================================================================

proptest! {
    /// Verify that requesting superset ops fails monotonicity check
    #[test]
    fn prop_monotonicity_rejects_superset(
        base_ops in prop::collection::vec("[a-z]+:[a-z]+:[0-9]+", 1..5),
        extra_op in "[a-z]+:[a-z]+:extra[0-9]+",
    ) {
        let parent_set = OperationSet::from_strings(
            &base_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        ).unwrap_or_else(|_| OperationSet::new());

        // Create proposed ops that include an extra operation
        let mut proposed_ops = base_ops.clone();
        proposed_ops.push(extra_op);
        let proposed_set = OperationSet::from_strings(
            &proposed_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        ).unwrap_or_else(|_| OperationSet::new());

        // INVARIANT: Superset must fail monotonicity check
        let result = parent_set.validate_monotonicity(&proposed_set);
        prop_assert!(
            result.is_err(),
            "Monotonicity check must reject superset operations"
        );
    }

    /// Verify that requesting subset ops succeeds monotonicity check
    #[test]
    fn prop_monotonicity_accepts_subset(
        all_ops in prop::collection::vec("[a-z]+:[a-z]+:[0-9]+", 2..10),
    ) {
        prop_assume!(all_ops.len() >= 2);

        let parent_set = OperationSet::from_strings(
            &all_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        ).unwrap_or_else(|_| OperationSet::new());

        // Create subset (first half of ops)
        let subset_size = all_ops.len() / 2;
        let subset_ops: Vec<_> = all_ops.iter().take(subset_size).cloned().collect();
        let subset = OperationSet::from_strings(
            &subset_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        ).unwrap_or_else(|_| OperationSet::new());

        // INVARIANT: Subset must succeed monotonicity check
        let result = parent_set.validate_monotonicity(&subset);
        prop_assert!(
            result.is_ok(),
            "Monotonicity check must accept strict subset operations"
        );
    }

    /// Verify that exact same ops succeeds (identity is a valid subset)
    #[test]
    fn prop_monotonicity_accepts_identity(
        ops in prop::collection::vec("[a-z]+:[a-z]+:[0-9]+", 1..5),
    ) {
        let op_strs: Vec<_> = ops.iter().map(|s| s.as_str()).collect();
        let set1 = OperationSet::from_strings(&op_strs).unwrap_or_else(|_| OperationSet::new());
        let set2 = OperationSet::from_strings(&op_strs).unwrap_or_else(|_| OperationSet::new());

        // INVARIANT: Same set is a valid subset (reflexive property)
        prop_assert!(
            set1.validate_monotonicity(&set2).is_ok(),
            "Same operations must be valid (reflexive subset)"
        );
    }
}

// =============================================================================
// INVARIANT 3: CONTINUITY - Hop numbers increase monotonically
// =============================================================================

proptest! {
    /// Verify hop numbers increase by exactly 1 at each step
    #[test]
    fn prop_hop_number_monotonic_increase(
        hops in 1..100u32,
    ) {
        let pca_0 = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:test"))
            .ops(vec!["*".into()])
            .build_pca_0()
            .unwrap();

        prop_assert_eq!(pca_0.hop, 0, "PCA_0 must have hop=0");

        let mut current = pca_0;
        for expected_hop in 1..=hops {
            let provenance = create_mock_provenance(expected_hop);
            let successor = PcaBuilder::new()
                .ops(vec!["read:*".into()])
                .build_successor(&current, provenance)
                .unwrap();

            // INVARIANT: hop must increase by exactly 1
            prop_assert_eq!(
                successor.hop,
                expected_hop,
                "Hop number must equal expected value"
            );
            prop_assert_eq!(
                successor.hop,
                current.hop + 1,
                "Hop must increase by exactly 1"
            );

            current = successor;
        }
    }

    /// Verify successor PCAs always have provenance
    #[test]
    fn prop_successor_has_provenance(hops in 1..20u32) {
        let pca_0 = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:test"))
            .ops(vec!["*".into()])
            .build_pca_0()
            .unwrap();

        prop_assert!(pca_0.provenance.is_none(), "PCA_0 must have no provenance");
        prop_assert!(pca_0.is_pca_0(), "PCA_0.is_pca_0() must be true");

        let mut current = pca_0;
        for hop in 1..=hops {
            let provenance = create_mock_provenance(hop);
            let successor = PcaBuilder::new()
                .ops(vec!["read:*".into()])
                .build_successor(&current, provenance)
                .unwrap();

            // INVARIANT: Successor must have provenance
            prop_assert!(
                successor.provenance.is_some(),
                "Successor at hop {} must have provenance",
                hop
            );
            prop_assert!(
                !successor.is_pca_0(),
                "Successor must not be PCA_0"
            );

            current = successor;
        }
    }
}

// =============================================================================
// WILDCARD OPERATION TESTS
// =============================================================================

proptest! {
    /// Verify wildcard ops contain more specific ops
    #[test]
    fn prop_wildcard_contains_specific(
        action in "[a-z]{3,8}",
        resource_prefix in "[a-z]{3,8}",
        resource_suffix in "[a-z0-9]{1,8}",
    ) {
        let wildcard_op = format!("{}:{}:*", action, resource_prefix);
        let specific_op = format!("{}:{}:{}", action, resource_prefix, resource_suffix);

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:test"))
            .ops(vec![wildcard_op.clone()])
            .build_pca_0()
            .unwrap();

        // INVARIANT: Wildcard must contain more specific operation
        prop_assert!(
            pca.contains_op(&specific_op),
            "Wildcard '{}' must contain '{}'",
            wildcard_op,
            specific_op
        );
    }

    /// Verify star (*) contains any operation
    #[test]
    fn prop_star_contains_any(
        op in "[a-z]+:[a-z]+:[a-z0-9]*",
    ) {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:test"))
            .ops(vec!["*".into()])
            .build_pca_0()
            .unwrap();

        // INVARIANT: "*" must contain any operation
        prop_assert!(
            pca.contains_op(&op),
            "'*' must contain any operation: {}",
            op
        );
    }

    /// Verify different action prefixes don't match
    #[test]
    fn prop_different_actions_no_match(
        action1 in "[a-z]{3,8}",
        action2 in "[a-z]{3,8}",
        resource in "[a-z]+",
    ) {
        prop_assume!(action1 != action2);

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:test"))
            .ops(vec![format!("{}:{}:*", action1, resource)])
            .build_pca_0()
            .unwrap();

        let different_action_op = format!("{}:{}:test", action2, resource);

        // INVARIANT: Different action must not match
        prop_assert!(
            !pca.contains_op(&different_action_op),
            "Different action '{}' should not be contained by '{}'",
            different_action_op,
            format!("{}:{}:*", action1, resource)
        );
    }
}

// =============================================================================
// SERIALIZATION ROUNDTRIP
// =============================================================================

proptest! {
    /// Verify PCA survives serialization roundtrip
    #[test]
    fn prop_pca_serialization_roundtrip(
        principal in "[a-z]{3,10}",
        num_ops in 1..5usize,
    ) {
        let ops: Vec<String> = (0..num_ops)
            .map(|i| format!("op{}:resource{}:*", i, i))
            .collect();

        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc(&format!("user:{}", principal)))
            .ops(ops)
            .executor(ExecutorBinding::new().with("service", "test"))
            .build_pca_0()
            .unwrap();

        let bytes = pca.to_bytes().unwrap();
        let restored = Pca::from_bytes(&bytes).unwrap();

        // INVARIANT: Serialization must preserve all fields
        prop_assert_eq!(pca.hop, restored.hop);
        prop_assert_eq!(pca.p_0, restored.p_0);
        prop_assert_eq!(pca.ops, restored.ops);
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn create_mock_provenance(hop: u32) -> Provenance {
    Provenance {
        cat_kid: format!("trust-plane-key-{}", hop),
        cat_sig: vec![0xCA, 0x7E, hop as u8],
        executor_kid: format!("executor-key-{}", hop),
        executor_sig: vec![0xE1, 0xEC, hop as u8],
    }
}

// =============================================================================
// ADDITIONAL UNIT TESTS (non-proptest)
// =============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_pca_0_has_no_provenance() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        assert!(pca.is_pca_0());
        assert!(pca.provenance.is_none());
        assert_eq!(pca.hop, 0);
    }

    #[test]
    fn test_pca_0_with_provenance_fails() {
        let result = PcaBuilder::new()
            .hop(0)
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .provenance(create_mock_provenance(0))
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_ops_monotonicity_empty_subset() {
        let parent = OperationSet::from_strings(&["read:data:*"]).unwrap();
        let empty = OperationSet::new();

        // Empty set is a valid subset of any set
        assert!(parent.validate_monotonicity(&empty).is_ok());
    }

    #[test]
    fn test_ops_monotonicity_with_wildcards() {
        let parent = OperationSet::from_strings(&["read:*"]).unwrap();
        let child = OperationSet::from_strings(&["read:data:123"]).unwrap();

        // Specific op is subset of wildcard
        assert!(parent.validate_monotonicity(&child).is_ok());
    }

    #[test]
    fn test_ops_monotonicity_rejects_broader_wildcard() {
        let parent = OperationSet::from_strings(&["read:data:*"]).unwrap();
        let child = OperationSet::from_strings(&["read:*"]).unwrap();

        // Broader wildcard is NOT subset of narrower
        assert!(parent.validate_monotonicity(&child).is_err());
    }

    #[test]
    fn test_chain_of_three_hops() {
        let pca_0 = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:*".into(), "write:data:*".into()])
            .build_pca_0()
            .unwrap();

        // Hop 1: Narrow to read:data:*
        let pca_1 = PcaBuilder::new()
            .ops(vec!["read:data:*".into()])
            .build_successor(&pca_0, create_mock_provenance(1))
            .unwrap();

        assert_eq!(pca_1.hop, 1);
        assert_eq!(pca_1.p_0, pca_0.p_0);

        // Hop 2: Narrow further to read:data:123
        let pca_2 = PcaBuilder::new()
            .ops(vec!["read:data:123".into()])
            .build_successor(&pca_1, create_mock_provenance(2))
            .unwrap();

        assert_eq!(pca_2.hop, 2);
        assert_eq!(pca_2.p_0, pca_0.p_0); // Still alice
    }
}

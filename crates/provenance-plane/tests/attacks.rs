//! Attack Scenario Tests
//!
//! These tests verify that specific attack patterns are prevented by the PIC model.
//! Each test represents a real-world attack scenario that must be blocked.

use provenance_core::{ExecutorBinding, OperationSet, Pca, PcaBuilder, PrincipalIdentifier, Provenance};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_mock_pca_0(principal: &str, ops: Vec<String>) -> Pca {
    PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc(principal))
        .ops(ops)
        .executor(ExecutorBinding::new().with("service", "test"))
        .build_pca_0()
        .expect("Failed to create mock PCA_0")
}

fn create_mock_provenance(hop: u32) -> Provenance {
    Provenance {
        cat_kid: format!("trust-plane-{}", hop),
        cat_sig: vec![0xCA, 0x7E, hop as u8],
        executor_kid: format!("executor-{}", hop),
        executor_sig: vec![0xEE, 0x1C, hop as u8],
    }
}

// =============================================================================
// ATTACK: Confused Deputy
// =============================================================================

/// The confused deputy attack: A service with broad authority is tricked into
/// using its own authority on behalf of a limited user.
///
/// Scenario: Service A has admin:* authority. Alice has read:data:alice/* only.
/// Service A processes Alice's request and might accidentally use its own
/// admin authority instead of Alice's limited authority.
///
/// PIC prevents this: The chain always carries Alice's authority (from her PCA),
/// not Service A's independent authority.
#[test]
fn attack_confused_deputy_prevented() {
    // Service A has broad authority (this is its own independent authority)
    let _service_a_pca = create_mock_pca_0(
        "service:service-a",
        vec!["admin:*".into(), "read:*".into(), "write:*".into()],
    );

    // Alice's authority is limited
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:alice/*".into()],
    );

    // Service A processes Alice's request
    // It MUST use Alice's PCA chain, not its own authority

    // Attack attempt: Service A tries to request broader ops than Alice has
    let attack_ops: Vec<String> = vec!["admin:*".into()]; // Broader than Alice's read:data:alice/*

    // Create the OperationSets for validation
    let alice_op_set = OperationSet::from_strings(
        &alice_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // MUST be rejected - admin:* is not in Alice's ops
    let result = alice_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Confused deputy attack must be blocked");
}

/// Even if Service A has admin rights independently, it cannot inject those
/// rights into Alice's chain.
#[test]
fn attack_authority_injection_prevented() {
    // Alice's limited authority
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:alice/*".into()],
    );

    // Create successor with Alice's authority (properly narrowed)
    let alice_pca_1 = PcaBuilder::new()
        .ops(vec!["read:data:alice/doc1".into()])
        .executor(ExecutorBinding::new().with("service", "service-a"))
        .build_successor(&alice_pca, create_mock_provenance(1))
        .unwrap();

    // Verify the chain still has Alice's identity
    assert_eq!(alice_pca_1.p_0.value, "user:alice");

    // Verify the ops are still limited
    assert!(!alice_pca_1.contains_op("admin:*"));
    assert!(!alice_pca_1.contains_op("write:data:alice/doc1"));
    assert!(alice_pca_1.contains_op("read:data:alice/doc1"));
}

// =============================================================================
// ATTACK: p_0 Modification
// =============================================================================

/// Attacker tries to change p_0 during the chain to gain another user's access.
///
/// Scenario: Alice's request is being processed. Attacker (or malicious service)
/// tries to change p_0 from "alice" to "bob" to access Bob's data.
///
/// PIC prevents this: build_successor() always copies p_0 from predecessor.
#[test]
fn attack_p_0_modification_prevented() {
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:*".into()],
    );

    // Attack: Try to set p_0 to bob
    let pca_1 = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("user:bob")) // ATTACK: changing p_0
        .ops(vec!["read:data:bob/*".into()]) // Trying to access Bob's data
        .build_successor(&alice_pca, create_mock_provenance(1))
        .unwrap();

    // p_0 MUST still be alice - the attack is neutralized
    assert_eq!(pca_1.p_0.value, "user:alice");
    assert_ne!(pca_1.p_0.value, "user:bob");
}

/// Multiple hops cannot change p_0
#[test]
fn attack_p_0_modification_multi_hop_prevented() {
    let alice_pca = create_mock_pca_0("user:alice", vec!["*".into()]);

    let mut current = alice_pca.clone();

    // Try to modify p_0 at each of 10 hops
    for hop in 1..=10 {
        let attacker_p_0 = format!("user:attacker{}", hop);

        let successor = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc(&attacker_p_0)) // ATTACK
            .ops(vec!["read:*".into()])
            .build_successor(&current, create_mock_provenance(hop))
            .unwrap();

        // p_0 must ALWAYS be alice
        assert_eq!(
            successor.p_0.value, "user:alice",
            "p_0 was modified at hop {}", hop
        );

        current = successor;
    }
}

// =============================================================================
// ATTACK: Privilege Escalation
// =============================================================================

/// Attacker tries to request MORE ops than predecessor has.
///
/// Scenario: User has read:data:* and requests write:data:* in successor.
///
/// PIC prevents this: Monotonicity check rejects ops not in predecessor.
#[test]
fn attack_privilege_escalation_prevented() {
    let limited_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:*".into()], // Only read
    );

    // Attack: Request write ops
    let attack_ops: Vec<String> = vec!["write:data:*".into()];

    let limited_op_set = OperationSet::from_strings(
        &limited_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // Monotonicity check MUST fail
    let result = limited_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Privilege escalation must be blocked");
}

/// Attacker tries to broaden wildcard scope
#[test]
fn attack_wildcard_broadening_prevented() {
    let narrow_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:alice/*".into()], // Only alice's data
    );

    // Attack: Try to get access to all data
    let attack_ops: Vec<String> = vec!["read:data:*".into()]; // Broader wildcard

    let narrow_op_set = OperationSet::from_strings(
        &narrow_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // Broader wildcard must be rejected
    let result = narrow_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Wildcard broadening must be blocked");
}

/// Attacker tries to add an extra operation type
#[test]
fn attack_add_extra_operation_prevented() {
    let pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:*".into(), "write:data:*".into()],
    );

    // Attack: Try to get delete permission (not in original)
    let attack_ops: Vec<String> = vec!["delete:data:*".into()];

    let pca_op_set = OperationSet::from_strings(
        &pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // Extra operation must be rejected
    let result = pca_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Extra operation must be blocked");
}

// =============================================================================
// ATTACK: Cross-Tenant Access
// =============================================================================

/// Attacker tries to access another tenant's resources through the chain.
///
/// Scenario: Alice has access to tenant-a/* but tries to access tenant-b/*.
#[test]
fn attack_cross_tenant_access_prevented() {
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:tenant-a:*".into()], // Only tenant-a
    );

    // Attack: Request access to tenant-b
    let attack_ops: Vec<String> = vec!["read:tenant-b:*".into()];

    let alice_op_set = OperationSet::from_strings(
        &alice_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // Cross-tenant access must be rejected
    let result = alice_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Cross-tenant access must be blocked");
}

// =============================================================================
// ATTACK: Service Impersonation via Chain
// =============================================================================

/// Compromised service cannot exceed its received authority even if it
/// is compromised and tries to act maliciously.
#[test]
fn attack_compromised_service_constrained() {
    // Gateway receives user's authority
    let user_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:claims:alice/*".into()],
    );

    // Gateway creates successor for archive service (properly narrowed)
    let archive_pca = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "archive"))
        .build_successor(&user_pca, create_mock_provenance(1))
        .unwrap();

    // Archive is compromised and tries to access other users' data
    let attack_ops: Vec<String> = vec!["read:claims:bob/*".into()];

    let archive_op_set = OperationSet::from_strings(
        &archive_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // Even compromised archive cannot access bob's data
    let result = archive_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "Compromised service must be constrained");
}

/// Even if all intermediate services are compromised, they cannot
/// exceed the original user's authority.
#[test]
fn attack_full_chain_compromise_constrained() {
    // Original user has limited authority
    let user_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:data:alice/*".into()],
    );

    // Simulate chain of 5 "compromised" services
    let mut current = user_pca.clone();
    for hop in 1..=5 {
        let successor = PcaBuilder::new()
            .ops(vec!["read:data:alice/*".into()]) // Can't exceed this
            .executor(ExecutorBinding::new().with("service", format!("compromised-{}", hop)))
            .build_successor(&current, create_mock_provenance(hop))
            .unwrap();

        // Even compromised services:
        // - Cannot change p_0
        assert_eq!(successor.p_0.value, "user:alice");
        // - Cannot exceed original authority
        assert!(!successor.contains_op("admin:*"));
        assert!(!successor.contains_op("read:data:bob/*"));

        current = successor;
    }
}

// =============================================================================
// ATTACK: Bypass PCA Requirement
// =============================================================================

/// Test that operations cannot be performed without proper ops
#[test]
fn attack_operation_without_authority() {
    let empty_pca = create_mock_pca_0("user:alice", vec![]); // No ops at all

    // User cannot perform any operation
    assert!(!empty_pca.contains_op("read:anything"));
    assert!(!empty_pca.contains_op("write:anything"));
    assert!(!empty_pca.contains_op("admin:anything"));
}

// =============================================================================
// ATTACK: PCA_0 Forgery
// =============================================================================

/// Attacker cannot create a valid PCA_0 with provenance (would indicate forgery)
#[test]
fn attack_pca_0_with_provenance_rejected() {
    let result = PcaBuilder::new()
        .hop(0)
        .p_0(PrincipalIdentifier::oidc("user:attacker"))
        .ops(vec!["admin:*".into()])
        .provenance(Provenance {
            cat_kid: "fake-cat".into(),
            cat_sig: vec![0xBA, 0xAD],
            executor_kid: "fake-exec".into(),
            executor_sig: vec![0xFA, 0x1E],
        })
        .build();

    // PCA_0 with provenance is structurally invalid
    assert!(result.is_err(), "PCA_0 with provenance must be rejected");
}

// =============================================================================
// ATTACK: AI Agent Confused Deputy
// =============================================================================

/// Specific attack: AI agent tries to access data beyond user's authority
/// This is the primary use case PIC was designed to prevent.
#[test]
fn attack_ai_agent_confused_deputy() {
    // User Alice has access only to her own claims
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:claims:alice/*".into()],
    );

    // Gateway delegates to AI agent
    let agent_pca = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new()
            .with("service", "ai-agent")
            .with("tool", "get_claims"))
        .build_successor(&alice_pca, create_mock_provenance(1))
        .unwrap();

    // AI agent (via prompt injection or malicious intent) tries to access
    // Bob's claims
    let attack_ops: Vec<String> = vec!["read:claims:bob/*".into()];

    let agent_op_set = OperationSet::from_strings(
        &agent_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // MUST be blocked
    let result = agent_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "AI agent confused deputy attack must be blocked");
}

/// AI agent tries to request all claims (wildcard escalation)
#[test]
fn attack_ai_agent_wildcard_escalation() {
    let alice_pca = create_mock_pca_0(
        "user:alice",
        vec!["read:claims:alice/*".into()],
    );

    let agent_pca = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "ai-agent"))
        .build_successor(&alice_pca, create_mock_provenance(1))
        .unwrap();

    // Agent tries to list ALL claims in the system
    let attack_ops: Vec<String> = vec!["read:claims:*".into()]; // Broader than alice/*

    let agent_op_set = OperationSet::from_strings(
        &agent_pca.ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();
    let attack_op_set = OperationSet::from_strings(
        &attack_ops.iter().map(|s| s.as_str()).collect::<Vec<_>>()
    ).unwrap();

    // MUST be blocked
    let result = agent_op_set.validate_monotonicity(&attack_op_set);
    assert!(result.is_err(), "AI agent wildcard escalation must be blocked");
}

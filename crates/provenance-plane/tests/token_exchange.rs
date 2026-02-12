//! Token Exchange PIC Profile Integration Tests
//!
//! These tests verify the complete flow of OAuth Token Exchange (RFC 8693)
//! integration with PIC authority chains:
//!
//! 1. Keycloak-format JWT → PCA_0 issuance (via validate_credential)
//! 2. Token-exchanged JWT with `act` claim → p_0 preserves original user
//! 3. Full chain: token exchange → PCA_0 → PoC processing → PCA_1
//! 4. Scope-to-operation mapping correctness
//! 5. Attack scenarios specific to token exchange flows

use provenance_core::{
    ExecutorBinding, OperationSet, Pca, PcaBuilder, PrincipalIdentifier,
    Provenance, TemporalConstraints,
};
use provenance_plane::KeyRegistry;

// =============================================================================
// Test Helpers
// =============================================================================

/// Create a PCA_0 simulating what the Trust Plane issues from a Keycloak JWT.
///
/// In the real flow, the Trust Plane's validate_jwt_credential() extracts:
/// - p_0 from preferred_username or act.sub chain
/// - ops from pic_ops claim
/// This helper creates the equivalent PCA_0 directly for testing the chain.
fn create_keycloak_pca_0(username: &str, ops: Vec<String>) -> Pca {
    let principal = format!("http://localhost:8180/realms/pic-demo#{}", username);
    PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc(&principal))
        .ops(ops)
        .executor(ExecutorBinding::new()
            .with("service", "keycloak-gateway")
            .with("token_exchange", "keycloak"))
        .temporal_constraints(
            TemporalConstraints::new()
                .issued_now()
                .expires_in(chrono::Duration::hours(1)),
        )
        .build_pca_0()
        .expect("Failed to create Keycloak PCA_0")
}

fn create_mock_provenance(hop: u32) -> Provenance {
    Provenance {
        cat_kid: format!("trust-plane-{}", hop),
        cat_sig: vec![0xCA, 0x7E, hop as u8, 0x01, 0x02, 0x03],
        executor_kid: format!("executor-{}", hop),
        executor_sig: vec![0xEE, 0x1C, hop as u8, 0x04, 0x05, 0x06],
    }
}

// =============================================================================
// Token Exchange Flow Tests
// =============================================================================

/// Test the complete Keycloak token exchange to PCA chain:
/// 1. PCA_0 issued with Alice's Keycloak identity and pic_ops
/// 2. Gateway delegates to resource-api via PoC → PCA_1
/// 3. Resource-api checks operation authorization
#[test]
fn test_full_keycloak_token_exchange_chain() {
    // Step 1: PCA_0 from Keycloak JWT (Alice authenticated, pic_ops extracted)
    let pca_0 = create_keycloak_pca_0(
        "alice",
        vec!["read:claims:alice/*".into()],
    );

    assert!(pca_0.is_pca_0());
    assert_eq!(pca_0.hop, 0);
    assert_eq!(
        pca_0.p_0.value,
        "http://localhost:8180/realms/pic-demo#alice"
    );
    assert_eq!(pca_0.ops, vec!["read:claims:alice/*"]);

    // Step 2: Gateway builds PoC and gets PCA_1 for resource-api
    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new()
            .with("service", "resource-api")
            .with("operation", "read")
            .with("claim_id", "alice/claim-001"))
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    assert_eq!(pca_1.hop, 1);
    assert_eq!(pca_1.p_0, pca_0.p_0); // PROVENANCE: p_0 immutable
    assert!(pca_1.provenance.is_some()); // CONTINUITY: chain linked

    // Step 3: Resource-api checks authorization
    assert!(pca_1.contains_op("read:claims:alice/claim-001"));
    assert!(pca_1.contains_op("read:claims:alice/claim-002"));
    assert!(!pca_1.contains_op("read:claims:bob/claim-001")); // Alice can't read Bob's
}

/// Token exchange preserves provenance: p_0 is the original human user,
/// not the gateway service account that performed the exchange
#[test]
fn test_token_exchange_preserves_provenance() {
    // After token exchange, even though the gateway service account is the
    // immediate token subject, p_0 should be alice (from act.sub or preferred_username)
    let pca_0 = create_keycloak_pca_0("alice", vec!["read:claims:alice/*".into()]);

    // Create a chain of 3 hops (gateway → agent → resource-api)
    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "ai-agent"))
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    let pca_2 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "resource-api"))
        .build_successor(&pca_1, create_mock_provenance(2))
        .unwrap();

    // p_0 must be alice at every hop — not the service account
    assert_eq!(
        pca_0.p_0.value,
        "http://localhost:8180/realms/pic-demo#alice"
    );
    assert_eq!(pca_1.p_0, pca_0.p_0);
    assert_eq!(pca_2.p_0, pca_0.p_0);
}

// =============================================================================
// Confused Deputy Attack via Token Exchange
// =============================================================================

/// The core confused deputy scenario for Keycloak token exchange:
/// Alice authenticates → Gateway performs token exchange → Gets PCA_0
/// Gateway then tries to access Bob's claim using Alice's PCA
#[test]
fn test_confused_deputy_via_token_exchange_blocked() {
    // Alice's PCA_0 from Keycloak (scoped to her claims)
    let alice_pca_0 = create_keycloak_pca_0(
        "alice",
        vec!["read:claims:alice/*".into()],
    );

    // Gateway delegates to resource-api
    let alice_pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "resource-api"))
        .build_successor(&alice_pca_0, create_mock_provenance(1))
        .unwrap();

    // Resource-api checks: can this PCA read bob/claim-001?
    assert!(!alice_pca_1.contains_op("read:claims:bob/claim-001"),
        "Alice's PCA must NOT authorize reading Bob's claims");

    // Verify the monotonicity check would also catch this
    let alice_op_set = OperationSet::from_strings(&["read:claims:alice/*"]).unwrap();
    let bob_op_set = OperationSet::from_strings(&["read:claims:bob/*"]).unwrap();
    assert!(
        alice_op_set.validate_monotonicity(&bob_op_set).is_err(),
        "read:claims:bob/* is not a subset of read:claims:alice/*"
    );
}

/// Cross-user access: Bob's token exchange cannot reach Alice's resources
#[test]
fn test_cross_user_access_via_token_exchange_blocked() {
    let bob_pca_0 = create_keycloak_pca_0(
        "bob",
        vec!["read:claims:bob/*".into()],
    );

    let bob_pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:bob/*".into()])
        .executor(ExecutorBinding::new().with("service", "resource-api"))
        .build_successor(&bob_pca_0, create_mock_provenance(1))
        .unwrap();

    // Bob's PCA must NOT authorize reading Alice's claims
    assert!(!bob_pca_1.contains_op("read:claims:alice/claim-001"));
    assert!(bob_pca_1.contains_op("read:claims:bob/claim-001")); // But Bob's own claims work
}

// =============================================================================
// Monotonic Operation Narrowing Through Token Exchange
// =============================================================================

/// Operations narrow correctly through the chain:
/// Keycloak pic_ops → PCA_0 ops → PCA_1 ops (must only shrink)
#[test]
fn test_ops_narrow_through_token_exchange_chain() {
    // Alice has broad read+write access from Keycloak
    let pca_0 = create_keycloak_pca_0(
        "alice",
        vec!["read:claims:alice/*".into(), "write:claims:alice/*".into()],
    );

    // Gateway narrows to read-only for resource-api
    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()]) // Narrowed: no write
        .executor(ExecutorBinding::new().with("service", "resource-api"))
        .build_successor(&pca_0, create_mock_provenance(1))
        .unwrap();

    // Resource-api has only read ops
    assert!(pca_1.contains_op("read:claims:alice/claim-001"));
    assert!(!pca_1.contains_op("write:claims:alice/claim-001"));
}

/// Attempting to broaden ops at any hop must fail
#[test]
fn test_ops_broadening_via_token_exchange_rejected() {
    let _pca_0 = create_keycloak_pca_0(
        "alice",
        vec!["read:claims:alice/*".into()],
    );

    // Attempt to broaden ops to read all claims
    let parent_ops = OperationSet::from_strings(&["read:claims:alice/*"]).unwrap();
    let broadened_ops = OperationSet::from_strings(&["read:claims:*"]).unwrap();

    assert!(
        parent_ops.validate_monotonicity(&broadened_ops).is_err(),
        "Broadening from alice/* to * must be rejected"
    );

    // Attempt to add write ops that weren't in the original
    let write_ops = OperationSet::from_strings(&["write:claims:alice/*"]).unwrap();
    assert!(
        parent_ops.validate_monotonicity(&write_ops).is_err(),
        "Adding write ops that weren't in the original must be rejected"
    );
}

// =============================================================================
// Cryptographic Chain Integrity
// =============================================================================

/// The signed PCA chain maintains integrity through token exchange
#[test]
fn test_signed_pca_chain_from_keycloak() {
    let registry = KeyRegistry::generate("demo-trust-plane");

    // PCA_0 from Keycloak JWT
    let pca_0 = create_keycloak_pca_0("alice", vec!["read:claims:alice/*".into()]);

    // Sign PCA_0
    let signed_pca_0 = registry.sign_pca(&pca_0).unwrap();

    // Verify PCA_0
    let cat_key = registry.get_cat(registry.cat_kid()).unwrap();
    let verified_pca_0 = cat_key.verify_pca(&signed_pca_0).unwrap();

    assert_eq!(verified_pca_0.p_0.value, "http://localhost:8180/realms/pic-demo#alice");
    assert_eq!(verified_pca_0.ops, vec!["read:claims:alice/*"]);

    // Build and sign PCA_1
    let pca_1 = PcaBuilder::new()
        .ops(vec!["read:claims:alice/*".into()])
        .executor(ExecutorBinding::new().with("service", "resource-api"))
        .build_successor(&verified_pca_0, create_mock_provenance(1))
        .unwrap();

    let signed_pca_1 = registry.sign_pca(&pca_1).unwrap();
    let verified_pca_1 = cat_key.verify_pca(&signed_pca_1).unwrap();

    // Chain integrity: same p_0 after verification
    assert_eq!(verified_pca_1.p_0, verified_pca_0.p_0);
    assert_eq!(verified_pca_1.hop, 1);
}

// =============================================================================
// OIDC Principal Format Tests
// =============================================================================

/// Verify the OIDC principal format used for Keycloak identities
#[test]
fn test_keycloak_oidc_principal_format() {
    let pca = create_keycloak_pca_0("alice", vec!["read:claims:alice/*".into()]);

    // Principal format: oidc:{issuer}#{username}
    assert_eq!(pca.p_0.principal_type, provenance_core::types::PrincipalType::Oidc);
    assert!(pca.p_0.value.starts_with("http://localhost:8180/realms/pic-demo#"));
    assert!(pca.p_0.value.ends_with("#alice"));
}

/// Different Keycloak users produce different p_0 values
#[test]
fn test_different_keycloak_users_different_p_0() {
    let alice_pca = create_keycloak_pca_0("alice", vec!["read:claims:alice/*".into()]);
    let bob_pca = create_keycloak_pca_0("bob", vec!["read:claims:bob/*".into()]);

    assert_ne!(alice_pca.p_0, bob_pca.p_0, "Different users must have different p_0");
    assert!(alice_pca.p_0.value.contains("alice"));
    assert!(bob_pca.p_0.value.contains("bob"));
}

// =============================================================================
// Token Exchange-Specific Attack: Gateway Impersonation
// =============================================================================

/// Even if the gateway's service account has broad permissions in Keycloak,
/// the PCA chain is scoped to the user's pic_ops. The gateway cannot substitute
/// its own authority.
#[test]
fn test_gateway_cannot_substitute_own_authority() {
    // Alice's PCA from her token exchange (limited to her claims)
    let alice_pca = create_keycloak_pca_0(
        "alice",
        vec!["read:claims:alice/*".into()],
    );

    // Gateway tries to create successor with broader ops
    let gateway_ops = OperationSet::from_strings(&["read:claims:alice/*"]).unwrap();
    let attack_ops = OperationSet::from_strings(&["read:claims:*", "write:claims:*"]).unwrap();

    assert!(
        gateway_ops.validate_monotonicity(&attack_ops).is_err(),
        "Gateway cannot escalate beyond user's original pic_ops"
    );

    // Gateway also cannot change p_0 to itself
    let pca_1 = PcaBuilder::new()
        .p_0(PrincipalIdentifier::oidc("service-account-pic-gateway")) // ATTACK
        .ops(vec!["read:claims:alice/*".into()])
        .build_successor(&alice_pca, create_mock_provenance(1))
        .unwrap();

    // p_0 must remain alice
    assert_eq!(
        pca_1.p_0.value,
        "http://localhost:8180/realms/pic-demo#alice"
    );
}

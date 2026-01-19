//! PCA (Proof of Causal Authority) Types
//!
//! The PCA represents authority at execution hop i in the causal chain.
//! It embodies the three PIC invariants:
//!
//! 1. **PROVENANCE**: p_0 (origin principal) is IMMUTABLE throughout the chain
//! 2. **IDENTITY**: ops can only SHRINK (ops_{i+1} ⊆ ops_i)
//! 3. **CONTINUITY**: Cryptographic chain linking each hop via provenance
//!
//! A PCA_0 is issued at federation entry (hop 0) and has no provenance.
//! Successor PCAs (hop > 0) contain provenance linking to their predecessor.

use crate::error::{ProvenanceError, Result};
use crate::operation::OperationSet;
use crate::types::{Constraints, PrincipalIdentifier, TemporalConstraints};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Proof of Causal Authority - authority state at execution hop i
///
/// The PCA is the core credential in the PIC model. It carries:
/// - The immutable origin principal (p_0) who initiated the request
/// - The allowed operations at this hop (can only shrink from predecessor)
/// - Provenance linking to the predecessor PCA (for hop > 0)
/// - Optional constraints (temporal, budget, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pca {
    /// Hop number in the causal chain (0 for PCA_0)
    pub hop: u32,

    /// Origin principal - IMMUTABLE throughout the chain
    /// This is always copied from predecessor.p_0, never set from request
    pub p_0: PrincipalIdentifier,

    /// Allowed operations - can only SHRINK across hops
    /// ops_{i+1} ⊆ ops_i must always hold
    pub ops: Vec<String>,

    /// Executor binding - key-value metadata about the executor
    pub executor: ExecutorBinding,

    /// Provenance linking to predecessor (None for PCA_0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// Constraints (temporal, budget, environment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

/// Executor binding - metadata about who is executing at this hop
///
/// Common keys:
/// - "service": Service name
/// - "tool": For AI agents, the tool being invoked
/// - "agent_id": Unique agent identifier
/// - "task_id": The task/request ID
/// - "federation": Federation/realm
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorBinding(HashMap<String, String>);

impl ExecutorBinding {
    /// Create a new empty executor binding
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Add a key-value pair (builder pattern)
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    /// Get a value by key
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|s| s.as_str())
    }

    /// Check if a key exists
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over key-value pairs
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

impl From<HashMap<String, String>> for ExecutorBinding {
    fn from(map: HashMap<String, String>) -> Self {
        Self(map)
    }
}

impl IntoIterator for ExecutorBinding {
    type Item = (String, String);
    type IntoIter = std::collections::hash_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Provenance - cryptographic link to predecessor PCA
///
/// This establishes the CONTINUITY invariant by recording:
/// - Who signed the predecessor PCA (CAT key)
/// - The signature on the predecessor
/// - Who created this PoC (executor key)
/// - The signature on the PoC
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Key ID of the Trust Plane (CAT) that signed the predecessor PCA
    pub cat_kid: String,

    /// Signature bytes from the predecessor PCA (for verification)
    #[serde(with = "serde_bytes_base64")]
    pub cat_sig: Vec<u8>,

    /// Key ID of the executor that signed the PoC
    pub executor_kid: String,

    /// Signature bytes from the PoC (for verification)
    #[serde(with = "serde_bytes_base64")]
    pub executor_sig: Vec<u8>,
}

/// Base64 serialization for signature bytes
mod serde_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

impl Pca {
    /// Check if this is a PCA_0 (federation entry)
    pub fn is_pca_0(&self) -> bool {
        self.hop == 0 && self.provenance.is_none()
    }

    /// Validate temporal constraints
    pub fn validate_temporal(&self) -> Result<()> {
        if let Some(ref constraints) = self.constraints {
            if let Some(ref temporal) = constraints.temporal {
                temporal.is_valid().map_err(|e| match e {
                    "PCA expired" => {
                        let exp = temporal.exp.clone().unwrap_or_default();
                        ProvenanceError::PcaExpired(exp)
                    }
                    "PCA not yet valid" => {
                        let nbf = temporal.nbf.clone().unwrap_or_default();
                        ProvenanceError::PcaNotYetValid(nbf)
                    }
                    _ => ProvenanceError::ConstraintViolation(e.to_string()),
                })?;
            }
        }
        Ok(())
    }

    /// Check if an operation is allowed by this PCA
    ///
    /// Supports wildcard matching:
    /// - "read:claims:*" contains "read:claims:123"
    /// - "read:*" contains "read:claims:123"
    /// - "*" contains everything
    pub fn contains_op(&self, op: &str) -> bool {
        for allowed in &self.ops {
            if allowed == "*" {
                return true;
            }
            if allowed == op {
                return true;
            }
            // Wildcard matching
            if allowed.ends_with('*') {
                let prefix = &allowed[..allowed.len() - 1];
                if op.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }

    /// Get the operation set for this PCA
    pub fn operation_set(&self) -> OperationSet {
        OperationSet::from(self.ops.clone())
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(ProvenanceError::from)
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(ProvenanceError::from)
    }

    /// Create a builder for constructing PCAs
    pub fn builder() -> PcaBuilder {
        PcaBuilder::new()
    }
}

/// Builder for constructing PCA instances
///
/// # Example
///
/// ```ignore
/// let pca = PcaBuilder::new()
///     .hop(0)
///     .p_0(PrincipalIdentifier::oidc("user:alice"))
///     .ops(vec!["read:claims:*".into()])
///     .executor(ExecutorBinding::new().with("service", "gateway"))
///     .build()?;
/// ```
#[derive(Debug, Default)]
pub struct PcaBuilder {
    hop: Option<u32>,
    p_0: Option<PrincipalIdentifier>,
    ops: Vec<String>,
    executor: ExecutorBinding,
    provenance: Option<Provenance>,
    constraints: Option<Constraints>,
}

impl PcaBuilder {
    /// Create a new PCA builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hop number
    pub fn hop(mut self, hop: u32) -> Self {
        self.hop = Some(hop);
        self
    }

    /// Set the origin principal (p_0)
    ///
    /// CRITICAL: For successor PCAs, this MUST be copied from predecessor.p_0
    pub fn p_0(mut self, p_0: PrincipalIdentifier) -> Self {
        self.p_0 = Some(p_0);
        self
    }

    /// Set the origin principal from a string identifier
    pub fn p_0_string(mut self, p_0: impl Into<String>) -> Self {
        use crate::types::PrincipalType;
        self.p_0 = Some(PrincipalIdentifier::new(PrincipalType::Custom, p_0));
        self
    }

    /// Set allowed operations
    pub fn ops(mut self, ops: Vec<String>) -> Self {
        self.ops = ops;
        self
    }

    /// Add a single operation
    pub fn add_op(mut self, op: impl Into<String>) -> Self {
        self.ops.push(op.into());
        self
    }

    /// Set the executor binding
    pub fn executor(mut self, executor: ExecutorBinding) -> Self {
        self.executor = executor;
        self
    }

    /// Set provenance (for successor PCAs)
    pub fn provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Set constraints
    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Set temporal constraints
    pub fn temporal_constraints(mut self, temporal: TemporalConstraints) -> Self {
        let mut constraints = self.constraints.unwrap_or_default();
        constraints.temporal = Some(temporal);
        self.constraints = Some(constraints);
        self
    }

    /// Build the PCA
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<Pca> {
        let hop = self.hop.ok_or(ProvenanceError::MissingField("hop".into()))?;
        let p_0 = self.p_0.ok_or(ProvenanceError::MissingField("p_0".into()))?;

        // Validate: PCA_0 must have no provenance, successor must have provenance
        if hop == 0 && self.provenance.is_some() {
            return Err(ProvenanceError::ConstraintViolation(
                "PCA_0 must not have provenance".into(),
            ));
        }

        // Note: We allow building successor PCAs without provenance for testing,
        // but in production the Trust Plane will always set provenance

        Ok(Pca {
            hop,
            p_0,
            ops: self.ops,
            executor: self.executor,
            provenance: self.provenance,
            constraints: self.constraints,
        })
    }

    /// Build a PCA_0 (federation entry)
    ///
    /// This is a convenience method that ensures hop=0 and no provenance.
    pub fn build_pca_0(self) -> Result<Pca> {
        if self.provenance.is_some() {
            return Err(ProvenanceError::ConstraintViolation(
                "PCA_0 must not have provenance".into(),
            ));
        }

        let p_0 = self.p_0.ok_or(ProvenanceError::MissingField("p_0".into()))?;

        Ok(Pca {
            hop: 0,
            p_0,
            ops: self.ops,
            executor: self.executor,
            provenance: None,
            constraints: self.constraints,
        })
    }

    /// Build a successor PCA from a predecessor
    ///
    /// This enforces:
    /// - p_0 is copied from predecessor (PROVENANCE invariant)
    /// - hop is predecessor.hop + 1
    /// - ops must be provided (will be validated by Trust Plane)
    pub fn build_successor(self, predecessor: &Pca, provenance: Provenance) -> Result<Pca> {
        Ok(Pca {
            hop: predecessor.hop + 1,
            p_0: predecessor.p_0.clone(), // CRITICAL: Always copy from predecessor
            ops: self.ops,
            executor: self.executor,
            provenance: Some(provenance),
            constraints: self.constraints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pca_0_creation() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("https://idp.example/users/alice"))
            .ops(vec!["read:claims:*".into(), "write:claims:*".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build_pca_0()
            .unwrap();

        assert!(pca.is_pca_0());
        assert_eq!(pca.hop, 0);
        assert!(pca.provenance.is_none());
        assert_eq!(pca.ops.len(), 2);
    }

    #[test]
    fn test_pca_0_with_provenance_fails() {
        let result = PcaBuilder::new()
            .hop(0)
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .provenance(Provenance {
                cat_kid: "cat-1".into(),
                cat_sig: vec![1, 2, 3],
                executor_kid: "exec-1".into(),
                executor_sig: vec![4, 5, 6],
            })
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_executor_binding() {
        let binding = ExecutorBinding::new()
            .with("service", "gateway")
            .with("agent_id", "agent-123")
            .with("tool", "get_claims");

        assert_eq!(binding.get("service"), Some("gateway"));
        assert_eq!(binding.get("agent_id"), Some("agent-123"));
        assert_eq!(binding.get("tool"), Some("get_claims"));
        assert_eq!(binding.get("nonexistent"), None);
        assert_eq!(binding.len(), 3);
    }

    #[test]
    fn test_contains_op_exact() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:claims:123".into()])
            .build_pca_0()
            .unwrap();

        assert!(pca.contains_op("read:claims:123"));
        assert!(!pca.contains_op("read:claims:456"));
    }

    #[test]
    fn test_contains_op_wildcard() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:claims:*".into()])
            .build_pca_0()
            .unwrap();

        assert!(pca.contains_op("read:claims:123"));
        assert!(pca.contains_op("read:claims:456"));
        assert!(pca.contains_op("read:claims:alice/doc1"));
        assert!(!pca.contains_op("write:claims:123"));
    }

    #[test]
    fn test_contains_op_star_all() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["*".into()])
            .build_pca_0()
            .unwrap();

        assert!(pca.contains_op("read:claims:123"));
        assert!(pca.contains_op("write:anything:else"));
        assert!(pca.contains_op("delete:everything"));
    }

    #[test]
    fn test_successor_pca() {
        let pca_0 = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:claims:*".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build_pca_0()
            .unwrap();

        let provenance = Provenance {
            cat_kid: "trust-plane-1".into(),
            cat_sig: vec![1, 2, 3, 4],
            executor_kid: "gateway-key".into(),
            executor_sig: vec![5, 6, 7, 8],
        };

        let pca_1 = PcaBuilder::new()
            .ops(vec!["read:claims:123".into()])
            .executor(ExecutorBinding::new().with("service", "claims-service"))
            .build_successor(&pca_0, provenance)
            .unwrap();

        assert_eq!(pca_1.hop, 1);
        // CRITICAL: p_0 must be the same as predecessor
        assert_eq!(pca_1.p_0, pca_0.p_0);
        assert!(pca_1.provenance.is_some());
        assert!(!pca_1.is_pca_0());
    }

    #[test]
    fn test_p_0_immutability_in_successor() {
        let original_p_0 = PrincipalIdentifier::oidc("user:alice");
        let pca_0 = PcaBuilder::new()
            .p_0(original_p_0.clone())
            .ops(vec!["read:*".into()])
            .build_pca_0()
            .unwrap();

        // Even if we try to set a different p_0, build_successor ignores it
        let provenance = Provenance {
            cat_kid: "cat-1".into(),
            cat_sig: vec![],
            executor_kid: "exec-1".into(),
            executor_sig: vec![],
        };

        // Note: build_successor ignores the p_0 set on builder and uses predecessor's
        let pca_1 = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:bob")) // This will be ignored
            .ops(vec!["read:data:123".into()])
            .build_successor(&pca_0, provenance)
            .unwrap();

        // p_0 MUST be alice, not bob
        assert_eq!(pca_1.p_0.value, "user:alice");
        assert_eq!(pca_1.p_0, original_p_0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let pca = PcaBuilder::new()
            .p_0(PrincipalIdentifier::oidc("user:alice"))
            .ops(vec!["read:claims:*".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build_pca_0()
            .unwrap();

        let bytes = pca.to_bytes().unwrap();
        let restored = Pca::from_bytes(&bytes).unwrap();

        assert_eq!(pca, restored);
    }

    #[test]
    fn test_temporal_validation_valid() {
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
    fn test_temporal_validation_expired() {
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
}

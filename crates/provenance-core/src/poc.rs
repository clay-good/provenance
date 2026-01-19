//! PoC (Proof of Continuity) Types
//!
//! The PoC is what an executor sends to the Trust Plane to request a successor PCA.
//! It contains:
//! - The signed predecessor PCA (proving current authority)
//! - The successor request (what authority is being requested)
//! - Optional attestation (additional proof like TEE attestation)
//!
//! The Trust Plane validates the PoC and, if the three PIC invariants are satisfied,
//! issues a successor PCA.

use crate::error::{ProvenanceError, Result};
use crate::pca::ExecutorBinding;
use crate::types::Constraints;
use serde::{Deserialize, Serialize};

/// Proof of Continuity - request for a successor PCA
///
/// The PoC establishes the causal link between hops by containing:
/// 1. The predecessor PCA (signed, proving current authority)
/// 2. The successor request (what the executor wants)
/// 3. Optional attestation (additional proof)
///
/// The Trust Plane validates:
/// - Predecessor PCA signature is valid
/// - PoC signature is valid (from registered executor)
/// - Successor ops ⊆ predecessor ops (monotonicity)
/// - Temporal constraints are satisfied
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Poc {
    /// Signed predecessor PCA bytes (COSE_Sign1 encoded)
    #[serde(with = "serde_bytes_base64")]
    pub predecessor: Vec<u8>,

    /// What the executor is requesting for the successor PCA
    pub successor: SuccessorRequest,

    /// Optional additional attestation (TEE, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

/// Request for a successor PCA
///
/// This specifies what authority the executor wants in the successor.
/// The Trust Plane will validate that:
/// - ops ⊆ predecessor.ops (monotonicity)
/// - constraints do not exceed predecessor constraints
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SuccessorRequest {
    /// Requested operations - MUST be subset of predecessor
    pub ops: Vec<String>,

    /// Executor binding for the successor PCA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<ExecutorBinding>,

    /// Requested constraints (cannot exceed predecessor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
}

/// Additional attestation that can accompany a PoC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// Type of attestation
    #[serde(rename = "type")]
    pub attestation_type: AttestationType,

    /// Attestation data (format depends on type)
    #[serde(with = "serde_bytes_base64")]
    pub data: Vec<u8>,

    /// Optional metadata about the attestation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Types of attestations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationType {
    /// Intel SGX attestation
    Sgx,
    /// AMD SEV attestation
    Sev,
    /// ARM TrustZone attestation
    TrustZone,
    /// AWS Nitro attestation
    Nitro,
    /// Custom attestation
    Custom,
}

/// Base64 serialization for bytes
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

impl Poc {
    /// Create a new PoC
    pub fn new(predecessor: Vec<u8>, successor: SuccessorRequest) -> Self {
        Self {
            predecessor,
            successor,
            attestation: None,
        }
    }

    /// Add attestation to the PoC
    pub fn with_attestation(mut self, attestation: Attestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(ProvenanceError::from)
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(ProvenanceError::from)
    }

    /// Create a builder for constructing PoCs
    pub fn builder(predecessor_pca_bytes: Vec<u8>) -> PocBuilder {
        PocBuilder::new(predecessor_pca_bytes)
    }
}

impl SuccessorRequest {
    /// Create a new successor request
    pub fn new(ops: Vec<String>) -> Self {
        Self {
            ops,
            executor: None,
            constraints: None,
        }
    }

    /// Set the executor binding
    pub fn with_executor(mut self, executor: ExecutorBinding) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Set constraints
    pub fn with_constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }
}

/// Builder for constructing PoC instances
///
/// # Example
///
/// ```ignore
/// let poc = PocBuilder::new(predecessor_pca_bytes)
///     .ops(vec!["read:claims:123".into()])
///     .executor(ExecutorBinding::new().with("service", "claims"))
///     .build()?;
/// ```
#[derive(Debug)]
pub struct PocBuilder {
    predecessor: Vec<u8>,
    ops: Vec<String>,
    executor: Option<ExecutorBinding>,
    constraints: Option<Constraints>,
    attestation: Option<Attestation>,
}

impl PocBuilder {
    /// Create a new PoC builder with the predecessor PCA bytes
    pub fn new(predecessor_pca_bytes: Vec<u8>) -> Self {
        Self {
            predecessor: predecessor_pca_bytes,
            ops: Vec::new(),
            executor: None,
            constraints: None,
            attestation: None,
        }
    }

    /// Set the requested operations
    ///
    /// These MUST be a subset of the predecessor's ops.
    /// The Trust Plane will validate this.
    pub fn ops(mut self, ops: Vec<String>) -> Self {
        self.ops = ops;
        self
    }

    /// Add a single operation
    pub fn add_op(mut self, op: impl Into<String>) -> Self {
        self.ops.push(op.into());
        self
    }

    /// Set the executor binding for the successor PCA
    pub fn executor(mut self, executor: ExecutorBinding) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Set constraints for the successor PCA
    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Add attestation
    pub fn attestation(mut self, attestation: Attestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Build the PoC
    ///
    /// This validates structure but NOT signatures (Trust Plane does that).
    pub fn build(self) -> Result<Poc> {
        if self.predecessor.is_empty() {
            return Err(ProvenanceError::MissingPredecessor);
        }

        let successor = SuccessorRequest {
            ops: self.ops,
            executor: self.executor,
            constraints: self.constraints,
        };

        let mut poc = Poc::new(self.predecessor, successor);

        if let Some(attestation) = self.attestation {
            poc = poc.with_attestation(attestation);
        }

        Ok(poc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_predecessor_bytes() -> Vec<u8> {
        // In real use, this would be a signed PCA
        b"mock-predecessor-pca".to_vec()
    }

    #[test]
    fn test_poc_creation() {
        let poc = PocBuilder::new(mock_predecessor_bytes())
            .ops(vec!["read:claims:123".into()])
            .executor(ExecutorBinding::new().with("service", "test"))
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops, vec!["read:claims:123"]);
        assert!(poc.successor.executor.is_some());
        assert!(poc.attestation.is_none());
    }

    #[test]
    fn test_poc_with_attestation() {
        let poc = PocBuilder::new(mock_predecessor_bytes())
            .ops(vec!["read:data:*".into()])
            .attestation(Attestation {
                attestation_type: AttestationType::Nitro,
                data: vec![1, 2, 3, 4],
                metadata: None,
            })
            .build()
            .unwrap();

        assert!(poc.attestation.is_some());
        let attestation = poc.attestation.unwrap();
        assert_eq!(attestation.attestation_type, AttestationType::Nitro);
    }

    #[test]
    fn test_poc_empty_predecessor_fails() {
        let result = PocBuilder::new(vec![]).ops(vec!["read:*".into()]).build();

        assert!(result.is_err());
        assert!(matches!(result, Err(ProvenanceError::MissingPredecessor)));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let poc = PocBuilder::new(mock_predecessor_bytes())
            .ops(vec!["read:claims:123".into(), "write:claims:456".into()])
            .executor(ExecutorBinding::new().with("service", "gateway"))
            .build()
            .unwrap();

        let bytes = poc.to_bytes().unwrap();
        let restored = Poc::from_bytes(&bytes).unwrap();

        assert_eq!(poc, restored);
    }

    #[test]
    fn test_successor_request() {
        let request = SuccessorRequest::new(vec!["read:*".into()])
            .with_executor(ExecutorBinding::new().with("tool", "search"))
            .with_constraints(Constraints::default());

        assert_eq!(request.ops, vec!["read:*"]);
        assert!(request.executor.is_some());
        assert!(request.constraints.is_some());
    }

    #[test]
    fn test_multiple_ops() {
        let poc = PocBuilder::new(mock_predecessor_bytes())
            .add_op("read:claims:alice/*")
            .add_op("write:claims:alice/*")
            .add_op("delete:claims:alice/temp")
            .build()
            .unwrap();

        assert_eq!(poc.successor.ops.len(), 3);
        assert!(poc.successor.ops.contains(&"read:claims:alice/*".to_string()));
        assert!(poc.successor.ops.contains(&"write:claims:alice/*".to_string()));
        assert!(poc.successor.ops.contains(&"delete:claims:alice/temp".to_string()));
    }
}

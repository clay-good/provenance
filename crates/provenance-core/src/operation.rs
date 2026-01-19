//! Operations and operation sets for authority management
//!
//! Operations represent authorized actions on resources. The PIC model
//! requires that operations can only contract (never expand) across hops.

use crate::error::{ProvenanceError, Result};
use serde::{Deserialize, Serialize};

/// An authorized operation on a resource
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Operation {
    /// Action to perform (read, write, invoke, delete, etc.)
    pub action: String,

    /// Resource pattern (supports wildcards: /user/*, api:claims:*)
    pub resource: String,

    /// Optional conditions on the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<OperationCondition>>,
}

/// Conditions that can be applied to an operation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationCondition {
    /// Type of condition
    #[serde(rename = "type")]
    pub condition_type: ConditionType,

    /// Condition parameters
    pub parameters: serde_json::Value,
}

/// Types of conditions that can be applied to operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionType {
    /// Temporal condition (time window)
    Temporal,
    /// IP-based condition
    Ip,
    /// Region-based condition
    Region,
    /// Cost-based condition
    Cost,
    /// Custom condition
    Custom,
}

impl Operation {
    /// Create a new operation
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            conditions: None,
        }
    }

    /// Parse an operation from a string like "read:/user/*"
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ProvenanceError::InvalidOperation(format!(
                "Expected 'action:resource', got '{}'",
                s
            )));
        }

        Ok(Self::new(parts[0], parts[1]))
    }

    /// Convert to string representation
    pub fn to_string_repr(&self) -> String {
        format!("{}:{}", self.action, self.resource)
    }

    /// Add a condition to the operation
    pub fn with_condition(mut self, condition: OperationCondition) -> Self {
        self.conditions
            .get_or_insert_with(Vec::new)
            .push(condition);
        self
    }

    /// Check if this operation matches another (for subset checking)
    ///
    /// An operation A matches B if:
    /// - A.action == B.action
    /// - A.resource matches B.resource (B can have wildcards)
    /// - A.conditions are at least as restrictive as B.conditions
    pub fn matches(&self, other: &Operation) -> bool {
        // Actions must match exactly
        if self.action != other.action {
            return false;
        }

        // Check resource pattern matching
        Self::resource_matches(&self.resource, &other.resource)
    }

    /// Check if a specific resource matches a pattern
    fn resource_matches(specific: &str, pattern: &str) -> bool {
        // Exact match
        if specific == pattern {
            return true;
        }

        // Wildcard matching
        if let Some(prefix) = pattern.strip_suffix('*') {
            return specific.starts_with(prefix);
        }

        false
    }
}

/// A set of operations representing authority
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationSet {
    operations: Vec<Operation>,
}

impl OperationSet {
    /// Create a new empty operation set
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an operation set from a list of operations
    pub fn from_operations(operations: Vec<Operation>) -> Self {
        Self { operations }
    }

    /// Parse operations from string representations
    pub fn from_strings(ops: &[&str]) -> Result<Self> {
        let operations: Result<Vec<_>> = ops.iter().map(|s| Operation::parse(s)).collect();
        Ok(Self::from_operations(operations?))
    }

    /// Add an operation to the set
    pub fn add(&mut self, operation: Operation) {
        self.operations.push(operation);
    }

    /// Check if the set contains an operation
    pub fn contains(&self, operation: &Operation) -> bool {
        self.operations.iter().any(|op| operation.matches(op))
    }

    /// Check if this set is a subset of another
    ///
    /// This is the core monotonicity check: ops_{i+1} ⊆ ops_i
    pub fn is_subset_of(&self, other: &OperationSet) -> bool {
        self.operations.iter().all(|op| other.contains(op))
    }

    /// Get the operations in this set
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Get the number of operations
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Convert to string representations
    pub fn to_strings(&self) -> Vec<String> {
        self.operations.iter().map(|op| op.to_string_repr()).collect()
    }

    /// Validate monotonicity: ensure proposed ops are subset of current
    pub fn validate_monotonicity(&self, proposed: &OperationSet) -> Result<()> {
        for op in proposed.operations() {
            if !self.contains(op) {
                return Err(ProvenanceError::MonotonicityViolation(op.to_string_repr()));
            }
        }
        Ok(())
    }
}

impl From<Vec<String>> for OperationSet {
    fn from(strings: Vec<String>) -> Self {
        let operations = strings
            .iter()
            .filter_map(|s| Operation::parse(s).ok())
            .collect();
        Self::from_operations(operations)
    }
}

impl IntoIterator for OperationSet {
    type Item = Operation;
    type IntoIter = std::vec::IntoIter<Operation>;

    fn into_iter(self) -> Self::IntoIter {
        self.operations.into_iter()
    }
}

impl<'a> IntoIterator for &'a OperationSet {
    type Item = &'a Operation;
    type IntoIter = std::slice::Iter<'a, Operation>;

    fn into_iter(self) -> Self::IntoIter {
        self.operations.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_parse() {
        let op = Operation::parse("read:/user/*").unwrap();
        assert_eq!(op.action, "read");
        assert_eq!(op.resource, "/user/*");
    }

    #[test]
    fn test_operation_matches_exact() {
        let op1 = Operation::new("read", "/user/alice");
        let op2 = Operation::new("read", "/user/alice");
        assert!(op1.matches(&op2));
    }

    #[test]
    fn test_operation_matches_wildcard() {
        let specific = Operation::new("read", "/user/alice");
        let pattern = Operation::new("read", "/user/*");
        assert!(specific.matches(&pattern));
    }

    #[test]
    fn test_operation_no_match_different_action() {
        let op1 = Operation::new("read", "/user/alice");
        let op2 = Operation::new("write", "/user/alice");
        assert!(!op1.matches(&op2));
    }

    #[test]
    fn test_operation_set_subset() {
        let parent = OperationSet::from_strings(&["read:/user/*", "write:/user/*"]).unwrap();
        let child = OperationSet::from_strings(&["read:/user/alice"]).unwrap();

        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn test_monotonicity_validation() {
        let parent = OperationSet::from_strings(&["read:/user/*"]).unwrap();
        let valid_child = OperationSet::from_strings(&["read:/user/alice"]).unwrap();
        let invalid_child = OperationSet::from_strings(&["write:/user/alice"]).unwrap();

        assert!(parent.validate_monotonicity(&valid_child).is_ok());
        assert!(parent.validate_monotonicity(&invalid_child).is_err());
    }
}

//! Common types used across the Provenance framework

use serde::{Deserialize, Serialize};

/// Principal identifier representing the origin of authority
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalIdentifier {
    /// Type of principal (oidc, spiffe, did, x509, custom)
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,

    /// Principal value (e.g., "https://idp.example/users/alice")
    pub value: String,

    /// Optional additional claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

/// Types of principal identifiers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalType {
    /// OpenID Connect / OAuth2
    Oidc,
    /// SPIFFE identity
    Spiffe,
    /// Decentralized Identifier
    Did,
    /// X.509 certificate
    X509,
    /// API Key
    ApiKey,
    /// Custom identifier
    Custom,
}

impl PrincipalIdentifier {
    /// Create a new principal identifier
    pub fn new(principal_type: PrincipalType, value: impl Into<String>) -> Self {
        Self {
            principal_type,
            value: value.into(),
            claims: None,
        }
    }

    /// Create an OIDC principal
    pub fn oidc(value: impl Into<String>) -> Self {
        Self::new(PrincipalType::Oidc, value)
    }

    /// Create a SPIFFE principal
    pub fn spiffe(value: impl Into<String>) -> Self {
        Self::new(PrincipalType::Spiffe, value)
    }

    /// Create a DID principal
    pub fn did(value: impl Into<String>) -> Self {
        Self::new(PrincipalType::Did, value)
    }

    /// Add claims to the principal
    pub fn with_claims(mut self, claims: serde_json::Value) -> Self {
        self.claims = Some(claims);
        self
    }
}

/// Constraints that can be applied to a PCA
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Temporal constraints (iat, exp, nbf)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<TemporalConstraints>,

    /// Environment constraints (regions, IPs, TEE requirements)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentConstraints>,

    /// Budget constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetConstraints>,
}

/// Temporal constraints for PCA validity
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalConstraints {
    /// Issued at (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<String>,

    /// Expiration (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,

    /// Not before (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
}

impl TemporalConstraints {
    /// Create new temporal constraints
    pub fn new() -> Self {
        Self::default()
    }

    /// Set issued at to now
    pub fn issued_now(mut self) -> Self {
        self.iat = Some(chrono::Utc::now().to_rfc3339());
        self
    }

    /// Set expiration
    pub fn expires_in(mut self, duration: chrono::Duration) -> Self {
        self.exp = Some((chrono::Utc::now() + duration).to_rfc3339());
        self
    }

    /// Set not-before
    pub fn not_before(mut self, time: chrono::DateTime<chrono::Utc>) -> Self {
        self.nbf = Some(time.to_rfc3339());
        self
    }

    /// Check if the constraints are currently valid
    pub fn is_valid(&self) -> Result<(), &'static str> {
        let now = chrono::Utc::now();

        if let Some(ref exp) = self.exp {
            let exp_time = chrono::DateTime::parse_from_rfc3339(exp)
                .map_err(|_| "Invalid exp timestamp")?;
            if now > exp_time {
                return Err("PCA expired");
            }
        }

        if let Some(ref nbf) = self.nbf {
            let nbf_time = chrono::DateTime::parse_from_rfc3339(nbf)
                .map_err(|_| "Invalid nbf timestamp")?;
            if now < nbf_time {
                return Err("PCA not yet valid");
            }
        }

        Ok(())
    }
}

/// Environment constraints for PCA
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentConstraints {
    /// Allowed regions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regions: Option<Vec<String>>,

    /// Allowed IP ranges (CIDR notation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<String>>,

    /// TEE requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee: Option<Vec<TeeRequirement>>,
}

/// Trusted Execution Environment requirements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeeRequirement {
    /// Intel SGX
    Sgx,
    /// AMD SEV
    Sev,
    /// ARM TrustZone
    TrustZone,
    /// AWS Nitro Enclaves
    Nitro,
}

/// Budget constraints for cost control
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BudgetConstraints {
    /// Maximum cost allowed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<f64>,

    /// Currency for budget
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Budget period
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<BudgetPeriod>,
}

/// Budget period for cost tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetPeriod {
    /// Per request
    Request,
    /// Per hour
    Hourly,
    /// Per day
    Daily,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_identifier() {
        let principal = PrincipalIdentifier::oidc("https://idp.example/users/alice")
            .with_claims(serde_json::json!({ "role": "admin" }));

        assert_eq!(principal.principal_type, PrincipalType::Oidc);
        assert_eq!(principal.value, "https://idp.example/users/alice");
        assert!(principal.claims.is_some());
    }

    #[test]
    fn test_temporal_constraints() {
        let constraints = TemporalConstraints::new()
            .issued_now()
            .expires_in(chrono::Duration::hours(1));

        assert!(constraints.iat.is_some());
        assert!(constraints.exp.is_some());
        assert!(constraints.is_valid().is_ok());
    }
}

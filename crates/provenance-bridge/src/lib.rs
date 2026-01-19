//! Federation Bridge
//!
//! The Federation Bridge translates external credentials (JWT, API Keys, etc.)
//! into validated principals that can be used to issue PCA_0.
//!
//! ## Architecture
//!
//! The bridge maintains a registry of credential handlers, each responsible
//! for validating a specific type of credential:
//!
//! - **JWT/OIDC**: Validates JWTs against trusted issuers using JWKS
//! - **API Key**: Validates API keys against a backend (in-memory, Qiuth, etc.)
//! - **Mock**: For testing purposes
//!
//! ## Usage
//!
//! ```ignore
//! use provenance_bridge::{FederationBridge, handlers::*};
//!
//! let bridge = FederationBridge::new()
//!     .with_handler(JwtHandler::new()
//!         .with_issuer(JwtIssuerConfig::new(
//!             "https://accounts.google.com",
//!             "https://www.googleapis.com/oauth2/v3/certs",
//!         )))
//!     .with_handler(MockHandler::new());
//!
//! let validated = bridge.validate("eyJ...", CredentialType::Jwt).await?;
//! println!("Principal: {}", validated.principal);
//! ```
//!
//! ## Qiuth Integration
//!
//! The API Key handler includes a `QiuthBackend` stub for integration with
//! Qiuth's MFA-validated API key management system. The integration path:
//!
//! 1. User authenticates with Qiuth (including MFA)
//! 2. Qiuth issues an API key with scopes
//! 3. Federation Bridge validates the key via Qiuth
//! 4. Trust Plane issues PCA_0 with the validated principal

pub mod bridge;
pub mod error;
pub mod handlers;
pub mod types;

pub use bridge::{CredentialHandler, FederationBridge, FederationBridgeBuilder};
pub use error::{BridgeError, Result};
pub use types::{CredentialType, ValidatedCredential};

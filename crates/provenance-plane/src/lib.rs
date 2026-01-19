//! Trust Plane Server
//!
//! The Trust Plane is the CAT (Causal Authority Transition) service that:
//! - Issues PCA_0 at federation entry
//! - Processes PoC requests and issues successor PCAs
//! - Enforces the three PIC invariants
//! - Supports federation with other Trust Planes
//!
//! ## PIC Invariants
//!
//! 1. **PROVENANCE**: Origin principal (p₀) is immutable throughout the chain
//! 2. **IDENTITY**: Authority can only decrease (ops_{i+1} ⊆ ops_i)
//! 3. **CONTINUITY**: Each hop cryptographically proves causal link to predecessor
//!
//! ## API Endpoints
//!
//! ### Core Endpoints
//! - `GET /health` - Liveness check
//! - `GET /ready` - Readiness check with CAT info
//! - `POST /v1/pca/issue` - Issue PCA_0 from external credential
//! - `POST /v1/poc/process` - Process PoC and issue successor PCA
//! - `POST /v1/keys/executor` - Register executor public key
//! - `GET /v1/keys/executor` - List registered executor key IDs
//!
//! ### Federation Endpoints
//! - `GET /v1/federation/info` - Get this Trust Plane's info for discovery
//! - `POST /v1/federation/cats` - Register a federated CAT
//! - `GET /v1/federation/cats` - List all registered CATs
//! - `DELETE /v1/federation/cats/:kid` - Unregister a federated CAT
//! - `POST /v1/federation/verify` - Verify a PCA from any known Trust Plane
//! - `POST /v1/federation/discover` - Auto-discover and register a Trust Plane by URL

pub mod api;
pub mod core;
pub mod keys;
pub mod storage;

pub use api::handlers::{AppState, TrustPlaneConfig};
pub use api::create_router;
pub use keys::KeyRegistry;
pub use storage::{KeyStore, MemoryStore, CatInfo, ExecutorInfo};

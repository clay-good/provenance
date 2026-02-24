//! Trust Plane Server Binary
//!
//! Runs the Trust Plane HTTP server for PIC authority chain management.

use std::env;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use provenance_core::crypto::KeyPair;
use provenance_plane::{create_router, AppState, KeyRegistry, MemoryStore, TrustPlaneConfig};

/// Load or generate the CAT key pair.
///
/// Checks, in order:
/// 1. `TRUST_PLANE_CAT_KEY_PATH` — path to a 32-byte Ed25519 seed file
/// 2. `TRUST_PLANE_CAT_KEY_HEX` — hex-encoded 32-byte Ed25519 seed
/// 3. Falls back to random generation (development only)
fn load_or_generate_cat_key(cat_kid: &str) -> KeyRegistry {
    // Try file-based key
    if let Ok(path) = env::var("TRUST_PLANE_CAT_KEY_PATH") {
        match std::fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => {
                let seed: [u8; 32] = bytes.try_into().expect("checked length");
                let key_pair = KeyPair::from_bytes(cat_kid, &seed)
                    .expect("Invalid CAT key seed");
                info!(path = %path, kid = %cat_kid, "Loaded CAT key from file");
                return KeyRegistry::new(key_pair);
            }
            Ok(bytes) => {
                panic!(
                    "CAT key file at {} has invalid length {} (expected 32 bytes)",
                    path,
                    bytes.len()
                );
            }
            Err(e) => {
                panic!("Failed to read CAT key file at {}: {}", path, e);
            }
        }
    }

    // Try hex-encoded key from environment
    if let Ok(hex) = env::var("TRUST_PLANE_CAT_KEY_HEX") {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .expect("TRUST_PLANE_CAT_KEY_HEX must be valid hex");
        assert_eq!(bytes.len(), 32, "TRUST_PLANE_CAT_KEY_HEX must be 64 hex chars (32 bytes)");
        let seed: [u8; 32] = bytes.try_into().expect("checked length");
        let key_pair = KeyPair::from_bytes(cat_kid, &seed)
            .expect("Invalid CAT key seed from hex");
        info!(kid = %cat_kid, "Loaded CAT key from TRUST_PLANE_CAT_KEY_HEX");
        return KeyRegistry::new(key_pair);
    }

    // Fallback: generate random key (development only)
    info!(kid = %cat_kid, "Generating ephemeral CAT key (set TRUST_PLANE_CAT_KEY_PATH or TRUST_PLANE_CAT_KEY_HEX for persistence)");
    KeyRegistry::generate(cat_kid)
}

#[tokio::main]
async fn main() {
    // Initialize logging
    let log_level = env::var("TRUST_PLANE_LOG_LEVEL")
        .unwrap_or_else(|_| "info".into())
        .parse()
        .unwrap_or(Level::INFO);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    // Configuration
    let port: u16 = env::var("TRUST_PLANE_PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .expect("TRUST_PLANE_PORT must be a valid port number");

    let cat_kid = env::var("TRUST_PLANE_CAT_KID")
        .unwrap_or_else(|_| format!("trust-plane-{}", uuid::Uuid::new_v4()));

    let trust_plane_name = env::var("TRUST_PLANE_NAME").ok();
    let public_url = env::var("TRUST_PLANE_PUBLIC_URL").ok();

    // Initialize key registry (persisted via TRUST_PLANE_CAT_KEY_PATH or _HEX)
    let registry = load_or_generate_cat_key(&cat_kid);

    // Initialize storage
    // TODO: Use PostgresStore when TRUST_PLANE_DATABASE_URL is set
    let store: Arc<dyn provenance_plane::KeyStore> = Arc::new(MemoryStore::new());

    // Configuration
    let config = TrustPlaneConfig {
        trust_plane_name: trust_plane_name.clone(),
        public_url,
    };

    info!(
        cat_kid = %registry.cat_kid(),
        name = ?trust_plane_name,
        port = port,
        "Starting Trust Plane server"
    );

    // Create application state
    let state = Arc::new(AppState { registry, store, config });

    // Build router
    let app = create_router(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    info!(addr = %addr, "Trust Plane listening");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

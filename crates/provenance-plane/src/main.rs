//! Trust Plane Server Binary
//!
//! Runs the Trust Plane HTTP server for PIC authority chain management.

use std::env;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use provenance_plane::{create_router, AppState, KeyRegistry, MemoryStore, TrustPlaneConfig};

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

    // Initialize key registry
    // TODO: In production, load CAT key from TRUST_PLANE_CAT_KEY_PATH
    let registry = KeyRegistry::generate(&cat_kid);

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

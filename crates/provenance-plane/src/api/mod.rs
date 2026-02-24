//! API module for the Trust Plane server

pub mod error;
pub mod handlers;

use axum::{
    extract::State,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use handlers::AppState;

/// Build CORS layer from TRUST_PLANE_CORS_ORIGINS environment variable.
///
/// - If unset or "*", allows any origin (development default).
/// - Otherwise, comma-separated list of allowed origins.
fn build_cors_layer() -> CorsLayer {
    let origins_env = std::env::var("TRUST_PLANE_CORS_ORIGINS").unwrap_or_default();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any);

    if origins_env.is_empty() || origins_env == "*" {
        cors.allow_origin(Any)
    } else {
        let origins: Vec<_> = origins_env
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        cors.allow_origin(origins)
    }
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Readiness check response
#[derive(Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub cat_kid: String,
    pub executor_count: usize,
    pub federated_cat_count: usize,
}

/// Health check endpoint
///
/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// Readiness check endpoint
///
/// GET /ready
pub async fn ready(State(state): State<Arc<AppState>>) -> Json<ReadyResponse> {
    let federated_count = state.store.list_federated_cats().await.map(|v| v.len()).unwrap_or(0);

    Json(ReadyResponse {
        ready: true,
        cat_kid: state.registry.cat_kid().to_string(),
        executor_count: state.registry.executor_count(),
        federated_cat_count: federated_count,
    })
}

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    // CORS configuration — configurable via TRUST_PLANE_CORS_ORIGINS env var
    let cors = build_cors_layer();

    Router::new()
        // Health endpoints
        .route("/health", get(health))
        .route("/ready", get(ready))
        // PCA endpoints
        .route("/v1/pca/issue", post(handlers::issue_pca))
        // PoC endpoints
        .route("/v1/poc/process", post(handlers::process_poc))
        // Key management endpoints
        .route("/v1/keys/executor", post(handlers::register_executor))
        .route("/v1/keys/executor", get(handlers::list_executors))
        // Federation endpoints
        .route("/v1/federation/info", get(handlers::get_info))
        .route("/v1/federation/cats", post(handlers::register_cat))
        .route("/v1/federation/cats", get(handlers::list_cats))
        .route("/v1/federation/cats/{kid}", delete(handlers::unregister_cat))
        .route("/v1/federation/verify", post(handlers::verify_federated_pca))
        .route("/v1/federation/discover", post(handlers::discover_cat))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

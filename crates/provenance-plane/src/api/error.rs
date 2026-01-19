//! API error types and responses

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use crate::core::{MonotonicityError, TemporalError};

/// API error type
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Monotonicity violation")]
    MonotonicityViolation(MonotonicityError),

    #[error("Temporal constraint violation")]
    TemporalViolation(TemporalError),

    #[error("Unknown executor: {0}")]
    UnknownExecutor(String),

    #[error("Unknown CAT: {0}")]
    UnknownCat(String),

    #[error("Invalid signature")]
    InvalidSignature(String),

    #[error("Invalid credential")]
    InvalidCredential(String),
}

/// API error response body
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match &self {
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                msg.clone(),
                None,
            ),
            ApiError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                msg.clone(),
                None,
            ),
            ApiError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                msg.clone(),
                None,
            ),
            ApiError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                msg.clone(),
                None,
            ),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                msg.clone(),
                None,
            ),
            ApiError::MonotonicityViolation(err) => (
                StatusCode::FORBIDDEN,
                "MONOTONICITY_VIOLATION",
                "Operations exceed authorized scope".to_string(),
                Some(serde_json::json!({
                    "violating_ops": err.violating_ops,
                    "allowed_ops": err.predecessor_ops,
                    "requested_ops": err.successor_ops,
                })),
            ),
            ApiError::TemporalViolation(err) => (
                StatusCode::FORBIDDEN,
                "TEMPORAL_VIOLATION",
                err.to_string(),
                None,
            ),
            ApiError::UnknownExecutor(kid) => (
                StatusCode::UNAUTHORIZED,
                "UNKNOWN_EXECUTOR",
                format!("Executor '{}' is not registered", kid),
                None,
            ),
            ApiError::UnknownCat(kid) => (
                StatusCode::UNAUTHORIZED,
                "UNKNOWN_CAT",
                format!("CAT '{}' is not registered", kid),
                None,
            ),
            ApiError::InvalidSignature(msg) => (
                StatusCode::UNAUTHORIZED,
                "INVALID_SIGNATURE",
                msg.clone(),
                None,
            ),
            ApiError::InvalidCredential(msg) => (
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIAL",
                msg.clone(),
                None,
            ),
        };

        let body = ErrorResponse {
            error: message,
            code: code.to_string(),
            details,
        };

        (status, Json(body)).into_response()
    }
}

impl From<provenance_core::ProvenanceError> for ApiError {
    fn from(err: provenance_core::ProvenanceError) -> Self {
        match err {
            provenance_core::ProvenanceError::PcaExpired(exp) => {
                ApiError::TemporalViolation(TemporalError::Expired(exp))
            }
            provenance_core::ProvenanceError::PcaNotYetValid(nbf) => {
                ApiError::TemporalViolation(TemporalError::NotYetValid(nbf))
            }
            provenance_core::ProvenanceError::MonotonicityViolation(op) => {
                ApiError::Forbidden(format!("Operation '{}' not authorized", op))
            }
            provenance_core::ProvenanceError::UnknownExecutor(kid) => {
                ApiError::UnknownExecutor(kid)
            }
            provenance_core::ProvenanceError::UnknownCat(kid) => {
                ApiError::UnknownCat(kid)
            }
            provenance_core::ProvenanceError::CryptoError(msg) => {
                ApiError::InvalidSignature(msg)
            }
            provenance_core::ProvenanceError::SerializationError(msg) => {
                ApiError::BadRequest(format!("Serialization error: {}", msg))
            }
            _ => ApiError::Internal(err.to_string()),
        }
    }
}

impl From<MonotonicityError> for ApiError {
    fn from(err: MonotonicityError) -> Self {
        ApiError::MonotonicityViolation(err)
    }
}

impl From<TemporalError> for ApiError {
    fn from(err: TemporalError) -> Self {
        ApiError::TemporalViolation(err)
    }
}

impl From<base64::DecodeError> for ApiError {
    fn from(err: base64::DecodeError) -> Self {
        ApiError::BadRequest(format!("Invalid base64 encoding: {}", err))
    }
}

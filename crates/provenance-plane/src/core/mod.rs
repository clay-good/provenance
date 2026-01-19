//! Core logic for the Trust Plane

mod validation;

pub use validation::{validate_monotonicity, validate_temporal, MonotonicityError, TemporalError};

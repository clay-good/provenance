package com.provenance.keycloak.pic.trustplane;

/**
 * Exception thrown when communication with the Trust Plane fails.
 *
 * <p>This exception covers all failure modes in the Trust Plane HTTP API:
 * <ul>
 *   <li>{@link FailureType#UNREACHABLE} — network-level failure (DNS, connection refused)</li>
 *   <li>{@link FailureType#TIMEOUT} — HTTP call exceeded configured timeout</li>
 *   <li>{@link FailureType#REJECTED} — Trust Plane returned an error response (4xx/5xx)</li>
 *   <li>{@link FailureType#INVALID_RESPONSE} — response body was malformed or unparseable</li>
 *   <li>{@link FailureType#MONOTONICITY_VIOLATION} — Trust Plane detected ops ⊄ predecessor</li>
 * </ul>
 *
 * <p>The {@code PicTokenExchangeProvider} translates these into appropriate
 * OAuth error responses based on the failure type and the realm's fail-open setting.
 *
 * <p>Maps to Rust error types in {@code provenance-plane/src/api/error.rs}.
 */
public class TrustPlaneException extends Exception {

    /**
     * Classification of Trust Plane communication failures.
     *
     * <p>Each type maps to specific error handling behavior in the
     * token exchange provider:
     * <ul>
     *   <li>UNREACHABLE/TIMEOUT → may fail-open if configured</li>
     *   <li>REJECTED/MONOTONICITY_VIOLATION → always fail (security boundary)</li>
     *   <li>INVALID_RESPONSE → always fail (cannot trust corrupted data)</li>
     * </ul>
     */
    public enum FailureType {
        /** Trust Plane is unreachable (DNS resolution, connection refused, etc.). */
        UNREACHABLE,

        /** Trust Plane returned an error response (HTTP 4xx or 5xx). */
        REJECTED,

        /** Trust Plane call timed out. */
        TIMEOUT,

        /** Response body was malformed or could not be parsed. */
        INVALID_RESPONSE,

        /**
         * Trust Plane detected a monotonicity violation.
         * This means requested ops were not a subset of authorized ops.
         * Corresponds to Rust {@code ApiError::MonotonicityViolation}.
         */
        MONOTONICITY_VIOLATION
    }

    private final FailureType failureType;
    private final int httpStatus;
    private final String trustPlaneError;

    /**
     * Creates a TrustPlaneException for a failure with no HTTP response.
     *
     * @param failureType the type of failure
     * @param message human-readable description
     */
    public TrustPlaneException(FailureType failureType, String message) {
        this(failureType, message, 0, null, null);
    }

    /**
     * Creates a TrustPlaneException for a failure with no HTTP response but with a cause.
     *
     * @param failureType the type of failure
     * @param message human-readable description
     * @param cause the underlying cause
     */
    public TrustPlaneException(FailureType failureType, String message, Throwable cause) {
        this(failureType, message, 0, null, cause);
    }

    /**
     * Creates a TrustPlaneException for an HTTP error response from the Trust Plane.
     *
     * @param failureType the type of failure
     * @param message human-readable description
     * @param httpStatus the HTTP status code returned (0 if no HTTP response)
     * @param trustPlaneError the error body returned by the Trust Plane
     */
    public TrustPlaneException(FailureType failureType, String message,
                               int httpStatus, String trustPlaneError) {
        this(failureType, message, httpStatus, trustPlaneError, null);
    }

    /**
     * Full constructor.
     *
     * @param failureType the type of failure
     * @param message human-readable description
     * @param httpStatus the HTTP status code (0 if no HTTP response)
     * @param trustPlaneError the error body from Trust Plane (null if none)
     * @param cause the underlying cause (null if none)
     */
    public TrustPlaneException(FailureType failureType, String message,
                               int httpStatus, String trustPlaneError, Throwable cause) {
        super(message, cause);
        this.failureType = failureType;
        this.httpStatus = httpStatus;
        this.trustPlaneError = trustPlaneError;
    }

    /**
     * Returns the type of Trust Plane failure.
     *
     * @return the failure classification
     */
    public FailureType getFailureType() {
        return failureType;
    }

    /**
     * Returns the HTTP status code from the Trust Plane response.
     *
     * @return the HTTP status code, or 0 if no HTTP response was received
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    /**
     * Returns the error body from the Trust Plane response.
     *
     * @return the error body string, or null if none
     */
    public String getTrustPlaneError() {
        return trustPlaneError;
    }

    /**
     * Whether this failure is a transient network issue that might resolve
     * on retry (UNREACHABLE or TIMEOUT).
     *
     * <p>The realm's {@code failOpen} setting only applies to transient failures.
     * Security-critical failures (REJECTED, MONOTONICITY_VIOLATION) always fail closed.
     *
     * @return true if the failure is potentially transient
     */
    public boolean isTransient() {
        return failureType == FailureType.UNREACHABLE
            || failureType == FailureType.TIMEOUT;
    }
}

package com.provenance.keycloak.pic.exchange;

/**
 * Exception thrown when PIC token exchange processing fails.
 *
 * <p>This exception covers failures that occur during PIC-specific processing
 * within the token exchange flow, such as:
 * <ul>
 *   <li>Missing or invalid principal in the subject token</li>
 *   <li>Act claim chain exceeding maximum depth</li>
 *   <li>No valid PIC operations after intersection</li>
 *   <li>PIC not enabled for the realm or client</li>
 * </ul>
 *
 * <p>Each exception carries an {@link ErrorCode} that the
 * {@code PicTokenExchangeProvider} maps to the appropriate OAuth error response.
 */
public class PicExchangeException extends Exception {

    /**
     * Error codes for PIC exchange failures.
     * These map to OAuth 2.0 error codes in the token exchange response.
     */
    public enum ErrorCode {
        /** No principal could be extracted from the subject token. Maps to {@code invalid_grant}. */
        MISSING_PRINCIPAL("invalid_grant"),

        /** Act claim chain exceeds maximum allowed depth. Maps to {@code invalid_grant}. */
        ACT_CHAIN_TOO_DEEP("invalid_grant"),

        /** No valid operations after intersecting authorized and requested ops. Maps to {@code access_denied}. */
        NO_VALID_OPERATIONS("access_denied"),

        /** PIC is not enabled for the realm. Maps to {@code unsupported_token_type}. */
        PIC_NOT_ENABLED_REALM("unsupported_token_type"),

        /** PIC is not enabled for the requesting client. Maps to {@code unauthorized_client}. */
        PIC_NOT_ENABLED_CLIENT("unauthorized_client"),

        /** Trust Plane URL is not configured for the realm. Maps to {@code server_error}. */
        TRUST_PLANE_NOT_CONFIGURED("server_error"),

        /** Invalid subject token (expired, revoked, malformed). Maps to {@code invalid_grant}. */
        INVALID_SUBJECT_TOKEN("invalid_grant");

        private final String oauthError;

        ErrorCode(String oauthError) {
            this.oauthError = oauthError;
        }

        /**
         * Returns the corresponding OAuth 2.0 error code string.
         *
         * @return the OAuth error code (e.g., "invalid_grant", "access_denied")
         */
        public String getOauthError() {
            return oauthError;
        }
    }

    private final ErrorCode errorCode;

    /**
     * Creates a new PIC exchange exception.
     *
     * @param errorCode the error classification
     * @param message human-readable error description
     */
    public PicExchangeException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Creates a new PIC exchange exception with a cause.
     *
     * @param errorCode the error classification
     * @param message human-readable error description
     * @param cause the underlying cause
     */
    public PicExchangeException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns the PIC error code for this exception.
     *
     * @return the error code
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * Returns the corresponding OAuth 2.0 error code string.
     *
     * @return the OAuth error code
     */
    public String getOauthError() {
        return errorCode.getOauthError();
    }
}

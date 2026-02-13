package com.provenance.keycloak.pic;

/**
 * Constants and URNs for the PIC (Provenance Identity Continuity) Keycloak extension.
 *
 * <p>This class defines all string constants used across the PIC SPI modules,
 * including token type URNs, JWT claim names, realm/client/user attribute keys,
 * HTTP headers, and secure defaults.
 *
 * <p>Naming conventions:
 * <ul>
 *   <li>Realm attributes use the {@code pic_} prefix (underscore-separated)</li>
 *   <li>Client attributes use the {@code pic.} prefix (dot-separated)</li>
 *   <li>JWT claims use the {@code pic_} prefix (underscore-separated)</li>
 * </ul>
 */
public final class PicConstants {

    private PicConstants() {
        // Prevent instantiation
    }

    // =========================================================================
    // Token Type URN
    // =========================================================================

    /**
     * Custom token type URN for PIC-enhanced tokens.
     * Used as {@code requested_token_type} in RFC 8693 token exchange requests
     * and as {@code issued_token_type} in exchange responses.
     */
    public static final String PIC_TOKEN_TYPE =
        "urn:ietf:params:oauth:token-type:pic_token";

    // =========================================================================
    // JWT Header
    // =========================================================================

    /**
     * JWT {@code typ} header value for PIC tokens.
     * Distinguishes PIC tokens from standard JWTs and OAuth access tokens.
     */
    public static final String PIC_JWT_TYPE = "pic+jwt";

    // =========================================================================
    // JWT Claim Names
    // =========================================================================

    /**
     * Claim name for the PIC provenance anchor object.
     * Contains: version, p_0, pca_0_hash, cat_kid, hop, trust_plane.
     */
    public static final String CLAIM_PIC_PROVENANCE = "pic_provenance";

    /**
     * Claim name for the PIC operations array.
     * Contains the narrowed operations authorized at this hop.
     */
    public static final String CLAIM_PIC_OPS = "pic_ops";

    /**
     * Claim name for the PIC chain audit trail array.
     * Each entry records one hop: { hop, executor, ops, pca_hash, cat_kid }.
     */
    public static final String CLAIM_PIC_CHAIN = "pic_chain";

    // =========================================================================
    // Provenance Claim Sub-Fields
    // =========================================================================

    /** PIC claim version field name within {@code pic_provenance}. */
    public static final String PROV_VERSION = "version";

    /** Origin principal field name within {@code pic_provenance}. */
    public static final String PROV_P0 = "p_0";

    /** PCA hash field name within {@code pic_provenance}. Base64url-encoded SHA-256. */
    public static final String PROV_PCA_HASH = "pca_0_hash";

    /** Trust Plane key ID field name within {@code pic_provenance}. */
    public static final String PROV_CAT_KID = "cat_kid";

    /** Hop number field name within {@code pic_provenance}. */
    public static final String PROV_HOP = "hop";

    /** Trust Plane URL field name within {@code pic_provenance}. */
    public static final String PROV_TRUST_PLANE = "trust_plane";

    // =========================================================================
    // PIC Version
    // =========================================================================

    /** Current PIC claim format version. */
    public static final String PIC_VERSION = "1.0";

    // =========================================================================
    // Realm Attributes
    // =========================================================================

    /** Prefix for all PIC realm attributes. */
    public static final String REALM_ATTR_PREFIX = "pic_";

    /** Realm attribute: Whether PIC is enabled for this realm. */
    public static final String REALM_ATTR_ENABLED = "pic_enabled";

    /** Realm attribute: URL of the Trust Plane server. */
    public static final String REALM_ATTR_TRUST_PLANE_URL = "pic_trust_plane_url";

    /** Realm attribute: HTTP timeout for Trust Plane calls in milliseconds. */
    public static final String REALM_ATTR_TRUST_PLANE_TIMEOUT_MS = "pic_trust_plane_timeout_ms";

    /**
     * Realm attribute: Whether to fail open if Trust Plane is unreachable.
     * SECURITY WARNING: Setting this to {@code true} defeats PIC's security guarantees.
     */
    public static final String REALM_ATTR_FAIL_OPEN = "pic_fail_open";

    /** Realm attribute: User attribute name for PIC operations. */
    public static final String REALM_ATTR_OPS_ATTRIBUTE = "pic_ops_user_attribute";

    /** Realm attribute: Whether PIC audit logging is enabled. */
    public static final String REALM_ATTR_AUDIT_ENABLED = "pic_audit_enabled";

    /** Realm attribute: Maximum act claim chain depth before rejection. */
    public static final String REALM_ATTR_MAX_ACT_DEPTH = "pic_max_act_depth";

    /** Realm attribute: PIC token lifetime in seconds. */
    public static final String REALM_ATTR_TOKEN_LIFETIME_SECONDS = "pic_token_lifetime_seconds";

    // =========================================================================
    // Client Attributes
    // =========================================================================

    /** Client attribute: Whether PIC token exchange is enabled for this client. */
    public static final String CLIENT_ATTR_PIC_ENABLED = "pic.enabled";

    /** Client attribute: Service name used in executor binding metadata. */
    public static final String CLIENT_ATTR_PIC_EXECUTOR_NAME = "pic.executor.name";

    // =========================================================================
    // User Attributes
    // =========================================================================

    /** Default user attribute name for PIC operations. */
    public static final String DEFAULT_OPS_USER_ATTRIBUTE = "pic_ops";

    // =========================================================================
    // HTTP Headers
    // =========================================================================

    /** HTTP header for propagating signed PCA between services. */
    public static final String PCA_HEADER = "X-PIC-PCA";

    // =========================================================================
    // Defaults
    // =========================================================================

    /** Default HTTP timeout for Trust Plane calls in milliseconds. */
    public static final int DEFAULT_TRUST_PLANE_TIMEOUT_MS = 5000;

    /** Default maximum depth for act claim chain traversal. */
    public static final int DEFAULT_MAX_ACT_DEPTH = 32;

    /** Default PIC token lifetime in seconds (5 minutes). */
    public static final int DEFAULT_TOKEN_LIFETIME_SECONDS = 300;

    // =========================================================================
    // Principal Identifier Format
    // =========================================================================

    /** Principal type for OIDC-sourced principals. */
    public static final String PRINCIPAL_TYPE_OIDC = "oidc";

    /**
     * Format string for OIDC principal identifiers.
     * Pattern: {@code oidc:{issuer}#{subject}}
     */
    public static final String PRINCIPAL_FORMAT_OIDC = "oidc:%s#%s";
}

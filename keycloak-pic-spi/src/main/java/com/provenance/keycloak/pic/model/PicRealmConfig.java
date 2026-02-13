package com.provenance.keycloak.pic.model;

import com.provenance.keycloak.pic.PicConstants;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration model for PIC settings within a Keycloak realm.
 *
 * <p>All settings are stored as realm attributes with the {@code pic_} prefix.
 * This class provides bidirectional conversion between the typed Java model
 * and the string-based realm attribute map.
 *
 * <p>Security-relevant defaults:
 * <ul>
 *   <li>{@code enabled} = false (PIC is opt-in per realm)</li>
 *   <li>{@code failOpen} = false (always fail-closed if Trust Plane is down)</li>
 *   <li>{@code auditEnabled} = true (audit everything by default)</li>
 *   <li>{@code maxActDepth} = 32 (bounded recursion for act chains)</li>
 *   <li>{@code tokenLifetimeSeconds} = 300 (5-minute PIC tokens)</li>
 * </ul>
 */
public class PicRealmConfig {

    private boolean enabled;
    private String trustPlaneUrl;
    private int trustPlaneTimeoutMs = PicConstants.DEFAULT_TRUST_PLANE_TIMEOUT_MS;
    private boolean failOpen;
    private String opsUserAttribute = PicConstants.DEFAULT_OPS_USER_ATTRIBUTE;
    private boolean auditEnabled = true;
    private int maxActDepth = PicConstants.DEFAULT_MAX_ACT_DEPTH;
    private int tokenLifetimeSeconds = PicConstants.DEFAULT_TOKEN_LIFETIME_SECONDS;

    /**
     * Creates a PicRealmConfig with all defaults.
     */
    public PicRealmConfig() {
    }

    /**
     * Creates a PicRealmConfig from realm attributes.
     *
     * @param attributes the realm's attribute map
     * @return a populated PicRealmConfig
     */
    public static PicRealmConfig fromRealmAttributes(Map<String, String> attributes) {
        PicRealmConfig config = new PicRealmConfig();

        if (attributes == null) {
            return config;
        }

        String enabled = attributes.get(PicConstants.REALM_ATTR_ENABLED);
        if (enabled != null) {
            config.enabled = Boolean.parseBoolean(enabled);
        }

        String trustPlaneUrl = attributes.get(PicConstants.REALM_ATTR_TRUST_PLANE_URL);
        if (trustPlaneUrl != null && !trustPlaneUrl.isBlank()) {
            config.trustPlaneUrl = trustPlaneUrl.trim();
        }

        String timeoutMs = attributes.get(PicConstants.REALM_ATTR_TRUST_PLANE_TIMEOUT_MS);
        if (timeoutMs != null) {
            try {
                int parsed = Integer.parseInt(timeoutMs.trim());
                if (parsed > 0) {
                    config.trustPlaneTimeoutMs = parsed;
                }
            } catch (NumberFormatException ignored) {
                // Keep default
            }
        }

        String failOpen = attributes.get(PicConstants.REALM_ATTR_FAIL_OPEN);
        if (failOpen != null) {
            config.failOpen = Boolean.parseBoolean(failOpen);
        }

        String opsAttr = attributes.get(PicConstants.REALM_ATTR_OPS_ATTRIBUTE);
        if (opsAttr != null && !opsAttr.isBlank()) {
            config.opsUserAttribute = opsAttr.trim();
        }

        String auditEnabled = attributes.get(PicConstants.REALM_ATTR_AUDIT_ENABLED);
        if (auditEnabled != null) {
            config.auditEnabled = Boolean.parseBoolean(auditEnabled);
        }

        String maxActDepth = attributes.get(PicConstants.REALM_ATTR_MAX_ACT_DEPTH);
        if (maxActDepth != null) {
            try {
                int parsed = Integer.parseInt(maxActDepth.trim());
                if (parsed > 0) {
                    config.maxActDepth = parsed;
                }
            } catch (NumberFormatException ignored) {
                // Keep default
            }
        }

        String tokenLifetime = attributes.get(PicConstants.REALM_ATTR_TOKEN_LIFETIME_SECONDS);
        if (tokenLifetime != null) {
            try {
                int parsed = Integer.parseInt(tokenLifetime.trim());
                if (parsed > 0) {
                    config.tokenLifetimeSeconds = parsed;
                }
            } catch (NumberFormatException ignored) {
                // Keep default
            }
        }

        return config;
    }

    /**
     * Converts this config to a realm attributes map.
     *
     * @return map of attribute keys to string values
     */
    public Map<String, String> toRealmAttributes() {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PicConstants.REALM_ATTR_ENABLED, String.valueOf(enabled));
        if (trustPlaneUrl != null) {
            attrs.put(PicConstants.REALM_ATTR_TRUST_PLANE_URL, trustPlaneUrl);
        }
        attrs.put(PicConstants.REALM_ATTR_TRUST_PLANE_TIMEOUT_MS,
                  String.valueOf(trustPlaneTimeoutMs));
        attrs.put(PicConstants.REALM_ATTR_FAIL_OPEN, String.valueOf(failOpen));
        attrs.put(PicConstants.REALM_ATTR_OPS_ATTRIBUTE, opsUserAttribute);
        attrs.put(PicConstants.REALM_ATTR_AUDIT_ENABLED, String.valueOf(auditEnabled));
        attrs.put(PicConstants.REALM_ATTR_MAX_ACT_DEPTH, String.valueOf(maxActDepth));
        attrs.put(PicConstants.REALM_ATTR_TOKEN_LIFETIME_SECONDS,
                  String.valueOf(tokenLifetimeSeconds));
        return attrs;
    }

    // =========================================================================
    // Getters and Setters
    // =========================================================================

    /** Whether PIC is enabled for this realm. */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /** URL of the Trust Plane server. */
    public String getTrustPlaneUrl() {
        return trustPlaneUrl;
    }

    public void setTrustPlaneUrl(String trustPlaneUrl) {
        this.trustPlaneUrl = trustPlaneUrl;
    }

    /** HTTP timeout for Trust Plane calls (ms). */
    public int getTrustPlaneTimeoutMs() {
        return trustPlaneTimeoutMs;
    }

    public void setTrustPlaneTimeoutMs(int trustPlaneTimeoutMs) {
        this.trustPlaneTimeoutMs = trustPlaneTimeoutMs;
    }

    /**
     * Whether to fail open if Trust Plane is unreachable.
     *
     * <p>SECURITY WARNING: Setting this to {@code true} defeats PIC's security
     * guarantees. Only use for debugging/development.
     */
    public boolean isFailOpen() {
        return failOpen;
    }

    public void setFailOpen(boolean failOpen) {
        this.failOpen = failOpen;
    }

    /** User attribute name for PIC operations. */
    public String getOpsUserAttribute() {
        return opsUserAttribute;
    }

    public void setOpsUserAttribute(String opsUserAttribute) {
        this.opsUserAttribute = opsUserAttribute;
    }

    /** Whether PIC audit logging is enabled. */
    public boolean isAuditEnabled() {
        return auditEnabled;
    }

    public void setAuditEnabled(boolean auditEnabled) {
        this.auditEnabled = auditEnabled;
    }

    /** Maximum act claim chain depth. */
    public int getMaxActDepth() {
        return maxActDepth;
    }

    public void setMaxActDepth(int maxActDepth) {
        this.maxActDepth = maxActDepth;
    }

    /** PIC token lifetime in seconds. */
    public int getTokenLifetimeSeconds() {
        return tokenLifetimeSeconds;
    }

    public void setTokenLifetimeSeconds(int tokenLifetimeSeconds) {
        this.tokenLifetimeSeconds = tokenLifetimeSeconds;
    }
}

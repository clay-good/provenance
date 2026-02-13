package com.provenance.keycloak.pic.audit;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Structured audit model for PIC-relevant security events.
 *
 * <p>Each audit event captures the full context of a PIC exchange for
 * structured JSON logging. The format is compatible with the Trust Plane's
 * audit format, enabling correlation across the PIC infrastructure.
 *
 * <p>Event types:
 * <ul>
 *   <li>{@code pic_exchange} — Successful PCA issuance via token exchange</li>
 *   <li>{@code pic_exchange_denied} — Token exchange rejected (no valid ops, etc.)</li>
 *   <li>{@code pic_monotonicity_violation} — Ops narrowing invariant violated</li>
 *   <li>{@code pic_session_start} — User login (correlate future exchanges)</li>
 *   <li>{@code pic_session_end} — User logout</li>
 *   <li>{@code pic_config_change} — Admin modified PIC configuration</li>
 * </ul>
 *
 * <p>Example JSON output:
 * <pre>{@code
 * {
 *   "timestamp": "2026-02-12T14:30:00.000Z",
 *   "event": "pic_exchange",
 *   "realm": "pic-demo",
 *   "user_id": "alice-user-id",
 *   "username": "alice",
 *   "client_id": "pic-gateway",
 *   "p_0": "oidc:https://keycloak.example.com/realms/pic-demo#alice-user-id",
 *   "pic_ops": ["read:claims:alice/claim-001"],
 *   "pca_0_hash": "base64url(SHA-256(...))",
 *   "trust_plane": "https://trust-plane.example.com",
 *   "cat_kid": "trust-plane-key-1",
 *   "hop": 0,
 *   "exchange_duration_ms": 45,
 *   "outcome": "success"
 * }
 * }</pre>
 */
public class PicAuditEvent {

    /**
     * PIC audit event types.
     */
    public enum EventType {
        PIC_EXCHANGE("pic_exchange"),
        PIC_EXCHANGE_DENIED("pic_exchange_denied"),
        PIC_MONOTONICITY_VIOLATION("pic_monotonicity_violation"),
        PIC_SESSION_START("pic_session_start"),
        PIC_SESSION_END("pic_session_end"),
        PIC_CONFIG_CHANGE("pic_config_change");

        private final String value;

        EventType(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Exchange outcome.
     */
    public enum Outcome {
        SUCCESS("success"),
        DENIED("denied"),
        ERROR("error");

        private final String value;

        Outcome(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    private final Instant timestamp;
    private final EventType eventType;
    private final String realm;
    private String userId;
    private String username;
    private String clientId;
    private String p0;
    private List<String> picOps;
    private String pca0Hash;
    private String trustPlane;
    private String catKid;
    private Integer hop;
    private Long exchangeDurationMs;
    private Outcome outcome;
    private String errorDetail;

    /**
     * Creates a new PIC audit event with the required fields.
     *
     * @param eventType the PIC event type
     * @param realm the realm name
     */
    public PicAuditEvent(EventType eventType, String realm) {
        this.timestamp = Instant.now();
        this.eventType = eventType;
        this.realm = realm;
    }

    /**
     * Creates a new PIC audit event with a specific timestamp (for testing).
     *
     * @param timestamp the event timestamp
     * @param eventType the PIC event type
     * @param realm the realm name
     */
    PicAuditEvent(Instant timestamp, EventType eventType, String realm) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.realm = realm;
    }

    /**
     * Converts this audit event to a map suitable for JSON serialization.
     *
     * <p>Uses {@link LinkedHashMap} to preserve field ordering in output,
     * matching the spec's structured audit log format.
     *
     * @return ordered map representation of the audit event
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("timestamp", timestamp.toString());
        map.put("event", eventType.getValue());
        map.put("realm", realm);

        if (userId != null) {
            map.put("user_id", userId);
        }
        if (username != null) {
            map.put("username", username);
        }
        if (clientId != null) {
            map.put("client_id", clientId);
        }
        if (p0 != null) {
            map.put("p_0", p0);
        }
        if (picOps != null) {
            map.put("pic_ops", picOps);
        }
        if (pca0Hash != null) {
            map.put("pca_0_hash", pca0Hash);
        }
        if (trustPlane != null) {
            map.put("trust_plane", trustPlane);
        }
        if (catKid != null) {
            map.put("cat_kid", catKid);
        }
        if (hop != null) {
            map.put("hop", hop);
        }
        if (exchangeDurationMs != null) {
            map.put("exchange_duration_ms", exchangeDurationMs);
        }
        if (outcome != null) {
            map.put("outcome", outcome.getValue());
        }
        if (errorDetail != null) {
            map.put("error_detail", errorDetail);
        }

        return map;
    }

    // =========================================================================
    // Getters
    // =========================================================================

    public Instant getTimestamp() { return timestamp; }
    public EventType getEventType() { return eventType; }
    public String getRealm() { return realm; }
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getClientId() { return clientId; }
    public String getP0() { return p0; }
    public List<String> getPicOps() { return picOps; }
    public String getPca0Hash() { return pca0Hash; }
    public String getTrustPlane() { return trustPlane; }
    public String getCatKid() { return catKid; }
    public Integer getHop() { return hop; }
    public Long getExchangeDurationMs() { return exchangeDurationMs; }
    public Outcome getOutcome() { return outcome; }
    public String getErrorDetail() { return errorDetail; }

    // =========================================================================
    // Setters (builder-style, return this)
    // =========================================================================

    public PicAuditEvent userId(String userId) {
        this.userId = userId;
        return this;
    }

    public PicAuditEvent username(String username) {
        this.username = username;
        return this;
    }

    public PicAuditEvent clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public PicAuditEvent p0(String p0) {
        this.p0 = p0;
        return this;
    }

    public PicAuditEvent picOps(List<String> picOps) {
        this.picOps = picOps;
        return this;
    }

    public PicAuditEvent pca0Hash(String pca0Hash) {
        this.pca0Hash = pca0Hash;
        return this;
    }

    public PicAuditEvent trustPlane(String trustPlane) {
        this.trustPlane = trustPlane;
        return this;
    }

    public PicAuditEvent catKid(String catKid) {
        this.catKid = catKid;
        return this;
    }

    public PicAuditEvent hop(int hop) {
        this.hop = hop;
        return this;
    }

    public PicAuditEvent exchangeDurationMs(long exchangeDurationMs) {
        this.exchangeDurationMs = exchangeDurationMs;
        return this;
    }

    public PicAuditEvent outcome(Outcome outcome) {
        this.outcome = outcome;
        return this;
    }

    public PicAuditEvent errorDetail(String errorDetail) {
        this.errorDetail = errorDetail;
        return this;
    }
}

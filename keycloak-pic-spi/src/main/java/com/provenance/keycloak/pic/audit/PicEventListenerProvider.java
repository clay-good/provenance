package com.provenance.keycloak.pic.audit;

import com.provenance.keycloak.pic.PicConstants;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;

import java.util.Map;

/**
 * Event listener that captures PIC-relevant security events for auditing.
 *
 * <p>Events captured:
 * <ul>
 *   <li>{@link EventType#TOKEN_EXCHANGE} with PIC token type — log PCA issuance details</li>
 *   <li>{@link EventType#TOKEN_EXCHANGE_ERROR} — log failed PIC exchanges with reason</li>
 *   <li>{@link EventType#LOGIN} — correlate with PIC sessions</li>
 *   <li>{@link EventType#LOGOUT} — correlate with PIC sessions</li>
 *   <li>{@link EventType#CUSTOM_REQUIRED_ACTION} — PIC-specific admin actions</li>
 * </ul>
 *
 * <p>Output: Structured JSON logs compatible with the Trust Plane's audit format.
 *
 * <p><b>IMPORTANT:</b> The listener MUST NOT block the token exchange flow.
 * Audit failures are logged as warnings but do not prevent token issuance.
 */
public class PicEventListenerProvider implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(PicEventListenerProvider.class);
    private static final Logger AUDIT_LOG = Logger.getLogger("com.provenance.keycloak.pic.audit.PIC_AUDIT");

    /**
     * Detail key used by the PIC token exchange provider to record the
     * requested token type in Keycloak event details.
     */
    static final String DETAIL_REQUESTED_TOKEN_TYPE = "requested_token_type";
    static final String DETAIL_PIC_P0 = "pic_p_0";
    static final String DETAIL_PIC_OPS = "pic_ops";
    static final String DETAIL_PIC_PCA_HASH = "pic_pca_hash";
    static final String DETAIL_PIC_HOP = "pic_hop";
    static final String DETAIL_PIC_TRUST_PLANE = "pic_trust_plane";
    static final String DETAIL_PIC_CAT_KID = "pic_cat_kid";
    static final String DETAIL_PIC_DURATION_MS = "pic_exchange_duration_ms";

    @Override
    public void onEvent(Event event) {
        try {
            switch (event.getType()) {
                case TOKEN_EXCHANGE -> handleTokenExchange(event);
                case TOKEN_EXCHANGE_ERROR -> handleTokenExchangeError(event);
                case LOGIN -> handleLogin(event);
                case LOGOUT -> handleLogout(event);
                case CUSTOM_REQUIRED_ACTION -> handleCustomRequiredAction(event);
                default -> {
                    // Not a PIC-relevant event
                }
            }
        } catch (Exception e) {
            // MUST NOT block — audit failures are logged but never propagated
            LOG.warnv(e, "PIC audit event processing failed for event type {0}", event.getType());
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        try {
            handleAdminEvent(event, includeRepresentation);
        } catch (Exception e) {
            LOG.warnv(e, "PIC audit admin event processing failed for {0} on {1}",
                    event.getOperationType(), event.getResourcePath());
        }
    }

    @Override
    public void close() {
        // Per-request cleanup — nothing to clean up
    }

    // =========================================================================
    // Event Handlers
    // =========================================================================

    /**
     * Handles successful token exchange events.
     * Only logs if the exchange involved a PIC token type.
     */
    private void handleTokenExchange(Event event) {
        if (!isPicExchange(event)) {
            return;
        }

        Map<String, String> details = event.getDetails();
        PicAuditEvent audit = new PicAuditEvent(
                PicAuditEvent.EventType.PIC_EXCHANGE,
                event.getRealmName() != null ? event.getRealmName() : event.getRealmId()
        );

        audit.userId(event.getUserId())
             .username(extractUsername(event))
             .clientId(event.getClientId())
             .outcome(PicAuditEvent.Outcome.SUCCESS);

        if (details != null) {
            audit.p0(details.get(DETAIL_PIC_P0))
                 .pca0Hash(details.get(DETAIL_PIC_PCA_HASH))
                 .trustPlane(details.get(DETAIL_PIC_TRUST_PLANE))
                 .catKid(details.get(DETAIL_PIC_CAT_KID));

            String hopStr = details.get(DETAIL_PIC_HOP);
            if (hopStr != null) {
                try { audit.hop(Integer.parseInt(hopStr)); } catch (NumberFormatException ignored) {}
            }

            String durationStr = details.get(DETAIL_PIC_DURATION_MS);
            if (durationStr != null) {
                try { audit.exchangeDurationMs(Long.parseLong(durationStr)); } catch (NumberFormatException ignored) {}
            }

            String opsStr = details.get(DETAIL_PIC_OPS);
            if (opsStr != null) {
                audit.picOps(parseOpsFromDetail(opsStr));
            }
        }

        emitAuditLog(audit);
    }

    /**
     * Handles failed token exchange events.
     * Only logs if the exchange involved a PIC token type.
     */
    private void handleTokenExchangeError(Event event) {
        if (!isPicExchange(event)) {
            return;
        }

        String realmName = event.getRealmName() != null ? event.getRealmName() : event.getRealmId();

        // Determine the specific PIC error type
        PicAuditEvent.EventType auditType = PicAuditEvent.EventType.PIC_EXCHANGE_DENIED;
        String error = event.getError();
        if (error != null && error.contains("monotonicity")) {
            auditType = PicAuditEvent.EventType.PIC_MONOTONICITY_VIOLATION;
        }

        PicAuditEvent audit = new PicAuditEvent(auditType, realmName);
        audit.userId(event.getUserId())
             .username(extractUsername(event))
             .clientId(event.getClientId())
             .outcome(PicAuditEvent.Outcome.DENIED)
             .errorDetail(error);

        Map<String, String> details = event.getDetails();
        if (details != null) {
            audit.p0(details.get(DETAIL_PIC_P0));
            String opsStr = details.get(DETAIL_PIC_OPS);
            if (opsStr != null) {
                audit.picOps(parseOpsFromDetail(opsStr));
            }
        }

        emitAuditLog(audit);
    }

    /**
     * Handles login events for PIC session correlation.
     */
    private void handleLogin(Event event) {
        PicAuditEvent audit = new PicAuditEvent(
                PicAuditEvent.EventType.PIC_SESSION_START,
                event.getRealmName() != null ? event.getRealmName() : event.getRealmId()
        );

        audit.userId(event.getUserId())
             .username(extractUsername(event))
             .clientId(event.getClientId())
             .outcome(PicAuditEvent.Outcome.SUCCESS);

        emitAuditLog(audit);
    }

    /**
     * Handles logout events for PIC session correlation.
     */
    private void handleLogout(Event event) {
        PicAuditEvent audit = new PicAuditEvent(
                PicAuditEvent.EventType.PIC_SESSION_END,
                event.getRealmName() != null ? event.getRealmName() : event.getRealmId()
        );

        audit.userId(event.getUserId())
             .username(extractUsername(event))
             .clientId(event.getClientId())
             .outcome(PicAuditEvent.Outcome.SUCCESS);

        emitAuditLog(audit);
    }

    /**
     * Handles custom required action events for PIC-specific admin actions.
     */
    private void handleCustomRequiredAction(Event event) {
        if (!isPicRelevant(event)) {
            return;
        }

        PicAuditEvent audit = new PicAuditEvent(
                PicAuditEvent.EventType.PIC_CONFIG_CHANGE,
                event.getRealmName() != null ? event.getRealmName() : event.getRealmId()
        );

        audit.userId(event.getUserId())
             .username(extractUsername(event))
             .clientId(event.getClientId())
             .outcome(PicAuditEvent.Outcome.SUCCESS);

        Map<String, String> details = event.getDetails();
        if (details != null) {
            audit.errorDetail(details.get("custom_required_action"));
        }

        emitAuditLog(audit);
    }

    /**
     * Handles admin events for PIC configuration changes.
     *
     * <p>Captures admin changes to:
     * <ul>
     *   <li>Realm attributes with {@code pic_} prefix</li>
     *   <li>Client attributes with {@code pic.} prefix</li>
     *   <li>User attributes for {@code pic_ops}</li>
     * </ul>
     */
    private void handleAdminEvent(AdminEvent event, boolean includeRepresentation) {
        // Only capture CREATE, UPDATE, DELETE operations
        OperationType opType = event.getOperationType();
        if (opType != OperationType.CREATE && opType != OperationType.UPDATE
                && opType != OperationType.DELETE) {
            return;
        }

        String resourcePath = event.getResourcePath();
        if (resourcePath == null) {
            return;
        }

        // Check if this is a PIC-relevant resource change
        boolean isPicRelevant = false;
        if (includeRepresentation && event.getRepresentation() != null) {
            String repr = event.getRepresentation();
            isPicRelevant = repr.contains("\"pic_") || repr.contains("\"pic.");
        }

        // Also check resource path for user attribute changes
        if (!isPicRelevant && resourcePath.contains("/users/") && resourcePath.contains("/attributes")) {
            isPicRelevant = true;
        }

        if (!isPicRelevant) {
            return;
        }

        PicAuditEvent audit = new PicAuditEvent(
                PicAuditEvent.EventType.PIC_CONFIG_CHANGE,
                event.getRealmName() != null ? event.getRealmName() : event.getRealmId()
        );

        audit.outcome(PicAuditEvent.Outcome.SUCCESS)
             .errorDetail(opType.name() + " on " + resourcePath);

        if (event.getAuthDetails() != null) {
            audit.userId(event.getAuthDetails().getUserId())
                 .clientId(event.getAuthDetails().getClientId());
        }

        emitAuditLog(audit);
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /**
     * Checks if a Keycloak event represents a PIC token exchange.
     */
    private boolean isPicExchange(Event event) {
        Map<String, String> details = event.getDetails();
        if (details == null) {
            return false;
        }
        String requestedTokenType = details.get(DETAIL_REQUESTED_TOKEN_TYPE);
        return PicConstants.PIC_TOKEN_TYPE.equals(requestedTokenType);
    }

    /**
     * Checks if an event is PIC-relevant based on its details.
     */
    private boolean isPicRelevant(Event event) {
        Map<String, String> details = event.getDetails();
        if (details == null) {
            return false;
        }
        // PIC-relevant if any detail key/value contains "pic"
        for (Map.Entry<String, String> entry : details.entrySet()) {
            if (entry.getKey().contains("pic") || (entry.getValue() != null && entry.getValue().contains("pic"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the username from an event's details map.
     * Keycloak stores the username in the "username" detail key.
     */
    private String extractUsername(Event event) {
        Map<String, String> details = event.getDetails();
        if (details == null) {
            return null;
        }
        return details.get("username");
    }

    /**
     * Parses a PIC ops string from event details.
     * The ops may be stored as a JSON array string or space-delimited.
     */
    private java.util.List<String> parseOpsFromDetail(String opsStr) {
        if (opsStr == null || opsStr.isBlank()) {
            return java.util.List.of();
        }

        // If it looks like a JSON array, parse it
        if (opsStr.startsWith("[")) {
            try {
                // Simple JSON array parsing (reuse OpsResolver logic)
                String inner = opsStr.substring(1, opsStr.length() - 1).trim();
                if (inner.isEmpty()) {
                    return java.util.List.of();
                }
                java.util.List<String> ops = new java.util.ArrayList<>();
                for (String element : inner.split(",")) {
                    String trimmed = element.trim();
                    if (trimmed.length() >= 2) {
                        char first = trimmed.charAt(0);
                        char last = trimmed.charAt(trimmed.length() - 1);
                        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                            trimmed = trimmed.substring(1, trimmed.length() - 1);
                        }
                    }
                    if (!trimmed.isBlank()) {
                        ops.add(trimmed);
                    }
                }
                return ops;
            } catch (Exception e) {
                // Fall through to space-delimited parsing
            }
        }

        // Space-delimited
        return java.util.List.of(opsStr.split("\\s+"));
    }

    /**
     * Emits a structured audit log entry.
     *
     * <p>Uses a dedicated audit logger so that log routing can be configured
     * independently (e.g., to a separate audit file or to an external SIEM).
     */
    private void emitAuditLog(PicAuditEvent audit) {
        AUDIT_LOG.infov("PIC_AUDIT: {0}", audit.toMap());
    }
}

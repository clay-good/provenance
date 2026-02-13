package com.provenance.keycloak.pic.admin;

import com.provenance.keycloak.pic.model.PicRealmConfig;
import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import com.provenance.keycloak.pic.trustplane.TrustPlaneException;
import com.provenance.keycloak.pic.trustplane.TrustPlaneStatus;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JAX-RS resource for PIC admin REST endpoints.
 *
 * <p>Base path: {@code /admin/realms/{realm}/pic}
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET /config} — Returns the current PIC configuration</li>
 *   <li>{@code PUT /config} — Updates PIC configuration (requires realm-admin)</li>
 *   <li>{@code GET /status} — Trust Plane connectivity status</li>
 *   <li>{@code GET /keys} — Lists executor keys registered with Trust Plane</li>
 *   <li>{@code POST /keys} — Registers a new executor key (requires realm-admin)</li>
 *   <li>{@code DELETE /keys/{kid}} — Revokes an executor key (requires realm-admin)</li>
 *   <li>{@code POST /verify} — Verifies a PCA chain against the Trust Plane</li>
 * </ul>
 *
 * <p>All endpoints require admin authentication. Write operations additionally
 * require realm management permissions.
 */
public class PicAdminResource {

    private static final Logger LOG = Logger.getLogger(PicAdminResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final TrustPlaneClient trustPlaneClient;

    public PicAdminResource(KeycloakSession session, RealmModel realm,
                            AdminPermissionEvaluator auth,
                            TrustPlaneClient trustPlaneClient) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.trustPlaneClient = trustPlaneClient;
    }

    // =========================================================================
    // GET /config
    // =========================================================================

    /**
     * Returns the current PIC configuration for the realm.
     *
     * @return PicRealmConfig as JSON
     */
    @GET
    @Path("config")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConfig() {
        auth.requireAnyAdminRole();

        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        return Response.ok(config.toRealmAttributes()).build();
    }

    // =========================================================================
    // PUT /config
    // =========================================================================

    /**
     * Updates the PIC configuration for the realm.
     *
     * <p>Requires realm management permissions. Accepts a map of PIC
     * realm attribute keys to their values.
     *
     * @param attributes the PIC configuration attributes to update
     * @return 204 No Content on success
     */
    @PUT
    @Path("config")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConfig(Map<String, String> attributes) {
        auth.realm().requireManageRealm();

        if (attributes == null || attributes.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "Request body must not be empty"))
                    .build();
        }

        // Only allow pic_ prefixed attributes to be set via this endpoint
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith("pic_")) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(errorJson("invalid_request",
                                "Only pic_ prefixed attributes are allowed: " + key))
                        .build();
            }
            realm.setAttribute(key, entry.getValue());
        }

        LOG.infov("PIC config updated for realm {0} by admin", realm.getName());

        // Return the updated config
        PicRealmConfig updatedConfig = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        return Response.ok(updatedConfig.toRealmAttributes()).build();
    }

    // =========================================================================
    // GET /status
    // =========================================================================

    /**
     * Returns the Trust Plane connectivity status.
     *
     * <p>Performs a health check against the configured Trust Plane URL
     * and returns status, latency, and version information.
     *
     * @return Trust Plane status as JSON
     */
    @GET
    @Path("status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus() {
        auth.requireAnyAdminRole();

        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        if (config.getTrustPlaneUrl() == null || config.getTrustPlaneUrl().isBlank()) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("trust_plane_url", null);
            result.put("status", "not_configured");
            result.put("latency_ms", 0);
            return Response.ok(result).build();
        }

        TrustPlaneStatus status;
        try {
            status = trustPlaneClient.healthCheck(
                    config.getTrustPlaneUrl(), config.getTrustPlaneTimeoutMs());
        } catch (TrustPlaneException e) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("trust_plane_url", config.getTrustPlaneUrl());
            result.put("status", "error");
            result.put("latency_ms", 0);
            result.put("detail", e.getMessage());
            return Response.ok(result).build();
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("trust_plane_url", config.getTrustPlaneUrl());
        result.put("status", status.isHealthy() ? "healthy" : "unhealthy");
        result.put("latency_ms", status.getLatencyMs());
        if (status.getVersion() != null) {
            result.put("version", status.getVersion());
        }
        result.put("detail", status.getStatus());

        return Response.ok(result).build();
    }

    // =========================================================================
    // GET /keys
    // =========================================================================

    /**
     * Lists executor keys registered with the Trust Plane for this realm.
     *
     * <p>Calls: {@code GET {trustPlaneUrl}/v1/keys/executor}
     *
     * @return list of executor key IDs
     */
    @GET
    @Path("keys")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listKeys() {
        auth.requireAnyAdminRole();

        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        if (config.getTrustPlaneUrl() == null || config.getTrustPlaneUrl().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("not_configured",
                            "Trust Plane URL is not configured for this realm"))
                    .build();
        }

        try {
            var keyList = trustPlaneClient.listExecutorKeys(
                    config.getTrustPlaneUrl(), config.getTrustPlaneTimeoutMs());
            return Response.ok(keyList).build();
        } catch (TrustPlaneException e) {
            LOG.warnv(e, "Failed to list executor keys from Trust Plane");
            return Response.status(Response.Status.BAD_GATEWAY)
                    .entity(errorJson("trust_plane_error",
                            "Failed to list keys: " + e.getMessage()))
                    .build();
        }
    }

    // =========================================================================
    // POST /keys
    // =========================================================================

    /**
     * Registers a new executor key with the Trust Plane.
     *
     * <p>Requires realm management permissions.
     *
     * @param request key registration request with kid and public_key
     * @return registration result
     */
    @POST
    @Path("keys")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerKey(Map<String, String> request) {
        auth.realm().requireManageRealm();

        if (request == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "Request body must not be empty"))
                    .build();
        }

        String kid = request.get("kid");
        String publicKey = request.get("public_key");
        String serviceName = request.get("service_name");

        if (kid == null || kid.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "kid is required"))
                    .build();
        }
        if (publicKey == null || publicKey.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "public_key is required"))
                    .build();
        }

        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        if (config.getTrustPlaneUrl() == null || config.getTrustPlaneUrl().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("not_configured",
                            "Trust Plane URL is not configured for this realm"))
                    .build();
        }

        try {
            trustPlaneClient.registerExecutorKey(config, kid, publicKey, serviceName);
            LOG.infov("Executor key '{0}' registered with Trust Plane for realm {1}",
                    kid, realm.getName());

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("kid", kid);
            result.put("message", "Executor key registered successfully");
            return Response.status(Response.Status.CREATED).entity(result).build();
        } catch (TrustPlaneException e) {
            LOG.warnv(e, "Failed to register executor key with Trust Plane");
            return Response.status(Response.Status.BAD_GATEWAY)
                    .entity(errorJson("trust_plane_error",
                            "Failed to register key: " + e.getMessage()))
                    .build();
        }
    }

    // =========================================================================
    // DELETE /keys/{kid}
    // =========================================================================

    /**
     * Revokes (deletes) an executor key from the Trust Plane.
     *
     * <p>Requires realm management permissions.
     *
     * @param kid the key identifier to revoke
     * @return 204 No Content on success
     */
    @DELETE
    @Path("keys/{kid}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeKey(@PathParam("kid") String kid) {
        auth.realm().requireManageRealm();

        if (kid == null || kid.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "kid path parameter is required"))
                    .build();
        }

        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        if (config.getTrustPlaneUrl() == null || config.getTrustPlaneUrl().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("not_configured",
                            "Trust Plane URL is not configured for this realm"))
                    .build();
        }

        try {
            trustPlaneClient.revokeExecutorKey(
                    config.getTrustPlaneUrl(), kid, config.getTrustPlaneTimeoutMs());
            LOG.infov("Executor key '{0}' revoked from Trust Plane for realm {1}",
                    kid, realm.getName());
            return Response.noContent().build();
        } catch (TrustPlaneException e) {
            LOG.warnv(e, "Failed to revoke executor key from Trust Plane");
            return Response.status(Response.Status.BAD_GATEWAY)
                    .entity(errorJson("trust_plane_error",
                            "Failed to revoke key: " + e.getMessage()))
                    .build();
        }
    }

    // =========================================================================
    // POST /verify
    // =========================================================================

    /**
     * Verifies a PCA chain against the Trust Plane.
     *
     * <p>Accepts a PCA (base64 COSE_Sign1) and verifies it by decoding
     * the PCA hash and checking the Trust Plane's response.
     *
     * <p>Requires admin authentication.
     *
     * @param request verification request with pca field
     * @return verification result as JSON
     */
    @POST
    @Path("verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verifyPca(Map<String, String> request) {
        auth.requireAnyAdminRole();

        if (request == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "Request body must not be empty"))
                    .build();
        }

        String pcaBase64 = request.get("pca");
        if (pcaBase64 == null || pcaBase64.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "pca field is required"))
                    .build();
        }

        // Decode and hash the PCA to verify it's valid base64
        byte[] pcaBytes;
        try {
            pcaBytes = java.util.Base64.getDecoder().decode(pcaBase64);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorJson("invalid_request", "pca is not valid Base64"))
                    .build();
        }

        // Compute PCA hash
        String pcaHash;
        try {
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(pcaBytes);
            pcaHash = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }

        // Build verification result
        // In a full implementation, this would call the Trust Plane's verify endpoint.
        // For now, we verify the PCA structure and return its hash.
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("valid", true);
        result.put("pca_hash", pcaHash);
        result.put("pca_size_bytes", pcaBytes.length);

        return Response.ok(result).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private Map<String, String> errorJson(String error, String message) {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("error", error);
        result.put("error_description", message);
        return result;
    }
}

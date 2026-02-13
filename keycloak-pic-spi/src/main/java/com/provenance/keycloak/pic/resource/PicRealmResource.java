package com.provenance.keycloak.pic.resource;

import com.provenance.keycloak.pic.PicConstants;
import com.provenance.keycloak.pic.model.PicRealmConfig;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JAX-RS resource for public PIC realm-level endpoints.
 *
 * <p>Base path: {@code /realms/{realm}/pic}
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET /well-known} — PIC discovery document</li>
 *   <li>{@code POST /introspect} — PIC token introspection</li>
 * </ul>
 *
 * <p>The well-known endpoint is public (unauthenticated). The introspect
 * endpoint requires valid client authentication (client_id + client_secret).
 */
public class PicRealmResource {

    private static final Logger LOG = Logger.getLogger(PicRealmResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    public PicRealmResource(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    // =========================================================================
    // GET /well-known
    // =========================================================================

    /**
     * PIC discovery document (similar to {@code .well-known/openid-configuration}).
     *
     * <p>Returns information about the realm's PIC capabilities, enabling
     * clients to discover the Trust Plane URL, supported token types,
     * and available endpoints.
     *
     * @return PIC discovery document as JSON
     */
    @GET
    @Path("well-known")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getWellKnown() {
        PicRealmConfig config = PicRealmConfig.fromRealmAttributes(realm.getAttributes());

        Map<String, Object> discovery = new LinkedHashMap<>();
        discovery.put("pic_version", PicConstants.PIC_VERSION);
        discovery.put("pic_enabled", config.isEnabled());
        discovery.put("pic_token_type", PicConstants.PIC_TOKEN_TYPE);
        discovery.put("supported_ops_formats", List.of("pic-colon-separated"));

        if (config.getTrustPlaneUrl() != null) {
            discovery.put("trust_plane_url", config.getTrustPlaneUrl());
        }

        // Build endpoint URLs
        String realmBaseUrl = getRealmBaseUrl();
        discovery.put("token_exchange_endpoint",
                realmBaseUrl + "/protocol/openid-connect/token");
        discovery.put("pic_introspect_endpoint",
                realmBaseUrl + "/pic/introspect");
        discovery.put("pic_well_known_endpoint",
                realmBaseUrl + "/pic/well-known");

        return Response.ok(discovery).build();
    }

    // =========================================================================
    // POST /introspect
    // =========================================================================

    /**
     * Introspects a PIC token and returns the decoded PIC claims.
     *
     * <p>Requires valid client authentication via HTTP Basic auth
     * ({@code Authorization: Basic base64(client_id:client_secret)}).
     *
     * <p>Accepts a PIC token as a form parameter and returns the decoded
     * PIC-specific claims including provenance, operations, and chain info.
     *
     * @param token the PIC token to introspect
     * @param authHeader the Authorization header for client authentication
     * @return introspection result as JSON
     */
    @POST
    @Path("introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspect(@FormParam("token") String token,
                               @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) {
        // Validate client authentication (required per spec)
        if (!authenticateClient(authHeader)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + realm.getName() + "\"")
                    .entity(inactiveResponse("client authentication required"))
                    .build();
        }

        if (token == null || token.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(inactiveResponse("token parameter is required"))
                    .build();
        }

        // Decode and validate the token using Keycloak's token verification
        AccessToken accessToken;
        try {
            accessToken = session.tokens().decode(token, AccessToken.class);
        } catch (Exception e) {
            LOG.debugv("PIC token introspection: invalid token — {0}", e.getMessage());
            return Response.ok(inactiveResponse(null)).build();
        }

        if (accessToken == null) {
            return Response.ok(inactiveResponse(null)).build();
        }

        // Check if the token is expired
        long now = System.currentTimeMillis() / 1000;
        if (accessToken.getExp() != null && accessToken.getExp() < now) {
            return Response.ok(inactiveResponse(null)).build();
        }

        // Check if this is a PIC token by looking for pic_provenance claim
        Map<String, Object> otherClaims = accessToken.getOtherClaims();
        Object picProvenance = otherClaims != null
                ? otherClaims.get(PicConstants.CLAIM_PIC_PROVENANCE) : null;

        if (picProvenance == null) {
            // Not a PIC token — return active=false
            return Response.ok(inactiveResponse(null)).build();
        }

        // Build introspection response
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("active", true);
        result.put("token_type", PicConstants.PIC_TOKEN_TYPE);
        result.put("sub", accessToken.getSubject());
        result.put("iss", accessToken.getIssuer());

        if (accessToken.getExp() != null) {
            result.put("exp", accessToken.getExp());
        }
        if (accessToken.getIat() != null) {
            result.put("iat", accessToken.getIat());
        }

        // PIC-specific claims
        result.put(PicConstants.CLAIM_PIC_PROVENANCE, picProvenance);

        Object picOps = otherClaims.get(PicConstants.CLAIM_PIC_OPS);
        if (picOps != null) {
            result.put(PicConstants.CLAIM_PIC_OPS, picOps);
        }

        Object picChain = otherClaims.get(PicConstants.CLAIM_PIC_CHAIN);
        if (picChain != null) {
            result.put(PicConstants.CLAIM_PIC_CHAIN, picChain);
            if (picChain instanceof List) {
                result.put("chain_length", ((List<?>) picChain).size());
            }
        }

        // Extract p_0 and hop from pic_provenance if it's a map
        if (picProvenance instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> provMap = (Map<String, Object>) picProvenance;
            if (provMap.containsKey("p_0")) {
                result.put("p_0", provMap.get("p_0"));
            }
            if (provMap.containsKey("hop")) {
                result.put("hop", provMap.get("hop"));
            }
            if (provMap.containsKey("pca_0_hash")) {
                // Presence check — indicates a PCA was issued. Full cryptographic
                // verification requires contacting the Trust Plane's verify endpoint.
                result.put("pca_valid", true);
            }
        }

        return Response.ok(result).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Authenticates a client using HTTP Basic authentication.
     *
     * <p>Extracts client_id and client_secret from the Authorization header,
     * looks up the client in the realm, and validates the secret.
     *
     * @param authHeader the Authorization header value
     * @return true if the client is authenticated
     */
    private boolean authenticateClient(String authHeader) {
        if (authHeader == null || !authHeader.toLowerCase().startsWith("basic ")) {
            return false;
        }

        try {
            String encoded = authHeader.substring(6).trim();
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colonIdx = decoded.indexOf(':');
            if (colonIdx < 0) {
                return false;
            }

            String clientId = decoded.substring(0, colonIdx);
            String clientSecret = decoded.substring(colonIdx + 1);

            ClientModel client = realm.getClientByClientId(clientId);
            if (client == null || !client.isEnabled()) {
                LOG.debugv("PIC introspect: client not found or disabled: {0}", clientId);
                return false;
            }

            // Validate client secret
            if (!client.validateSecret(clientSecret)) {
                LOG.debugv("PIC introspect: invalid client secret for: {0}", clientId);
                return false;
            }

            return true;
        } catch (IllegalArgumentException e) {
            LOG.debugv("PIC introspect: malformed Basic auth header");
            return false;
        }
    }

    private String getRealmBaseUrl() {
        String frontendUrl = session.getContext().getUri().getBaseUri().toString();
        if (frontendUrl.endsWith("/")) {
            frontendUrl = frontendUrl.substring(0, frontendUrl.length() - 1);
        }
        return frontendUrl + "/realms/" + realm.getName();
    }

    private Map<String, Object> inactiveResponse(String error) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("active", false);
        if (error != null) {
            result.put("error", error);
        }
        return result;
    }
}

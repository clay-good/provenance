package com.provenance.keycloak.pic.exchange;

import com.provenance.keycloak.pic.PicConstants;
import com.provenance.keycloak.pic.model.PicChainEntry;
import com.provenance.keycloak.pic.model.PicProvenanceClaim;
import com.provenance.keycloak.pic.model.PicRealmConfig;
import com.provenance.keycloak.pic.trustplane.PcaIssuanceResult;
import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import com.provenance.keycloak.pic.trustplane.TrustPlaneException;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenCategory;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Core token exchange provider that intercepts RFC 8693 exchanges
 * requesting PIC tokens and enhances them with authority continuity.
 *
 * <p><b>SECURITY CRITICAL:</b> This provider enforces the bridge between OAuth
 * token exchange and PIC's three invariants:
 * <ol>
 *   <li><b>PROVENANCE:</b> Extract p_0 from the act claim chain (immutable origin)</li>
 *   <li><b>IDENTITY:</b> Narrow ops to intersection of requested and allowed</li>
 *   <li><b>CONTINUITY:</b> Obtain a signed PCA from the Trust Plane</li>
 * </ol>
 *
 * <p>If the Trust Plane is unreachable, the exchange MUST fail (fail-closed)
 * unless the realm has explicitly set {@code pic_fail_open=true} (not recommended).
 *
 * <p>This provider is registered via
 * {@link PicTokenExchangeProviderFactory} with provider ID {@code "pic-token-exchange"}
 * and order 100 (higher than the default provider's 0).
 *
 * @see PicTokenExchangeProviderFactory
 */
public class PicTokenExchangeProvider implements TokenExchangeProvider {

    private static final Logger LOG = Logger.getLogger(PicTokenExchangeProvider.class);

    private final KeycloakSession session;
    private final TrustPlaneClient trustPlaneClient;
    private final OpsResolver opsResolver;

    public PicTokenExchangeProvider(KeycloakSession session, TrustPlaneClient trustPlaneClient) {
        this.session = session;
        this.trustPlaneClient = trustPlaneClient;
        this.opsResolver = new OpsResolver();
    }

    // Visible for testing
    PicTokenExchangeProvider(KeycloakSession session, TrustPlaneClient trustPlaneClient,
                             OpsResolver opsResolver) {
        this.session = session;
        this.trustPlaneClient = trustPlaneClient;
        this.opsResolver = opsResolver;
    }

    // =========================================================================
    // TokenExchangeProvider SPI methods
    // =========================================================================

    /**
     * Returns {@code true} when this provider should handle the exchange.
     *
     * <p>Conditions (ALL must be true):
     * <ul>
     *   <li>{@code requested_token_type} equals {@link PicConstants#PIC_TOKEN_TYPE}</li>
     *   <li>Realm has {@code pic_enabled=true}</li>
     *   <li>Requesting client has {@code pic.enabled=true}</li>
     * </ul>
     */
    @Override
    public boolean supports(TokenExchangeContext context) {
        String requestedTokenType = context.getParams().getRequestedTokenType();
        if (!PicConstants.PIC_TOKEN_TYPE.equals(requestedTokenType)) {
            return false;
        }

        RealmModel realm = context.getRealm();
        PicRealmConfig realmConfig = PicRealmConfig.fromRealmAttributes(realm.getAttributes());
        if (!realmConfig.isEnabled()) {
            LOG.debugv("PIC not enabled for realm {0}", realm.getName());
            return false;
        }

        ClientModel client = context.getClient();
        String clientPicEnabled = client.getAttribute(PicConstants.CLIENT_ATTR_PIC_ENABLED);
        if (!"true".equalsIgnoreCase(clientPicEnabled)) {
            LOG.debugv("PIC not enabled for client {0} in realm {1}",
                client.getClientId(), realm.getName());
            return false;
        }

        return true;
    }

    /**
     * Executes the PIC-enhanced token exchange.
     *
     * <p>Steps:
     * <ol>
     *   <li>Load realm PIC configuration</li>
     *   <li>Validate and decode the subject token</li>
     *   <li>Extract p_0 (origin principal) from the token claims</li>
     *   <li>Compute effective PIC operations</li>
     *   <li>Call Trust Plane to issue PCA</li>
     *   <li>Build PIC-enhanced JWT response</li>
     * </ol>
     */
    @Override
    public Response exchange(TokenExchangeContext context) {
        RealmModel realm = context.getRealm();
        ClientModel client = context.getClient();

        // Step 1: Load realm PIC configuration
        PicRealmConfig realmConfig = PicRealmConfig.fromRealmAttributes(realm.getAttributes());

        if (realmConfig.getTrustPlaneUrl() == null || realmConfig.getTrustPlaneUrl().isBlank()) {
            LOG.errorv("Trust Plane URL not configured for realm {0}", realm.getName());
            throw new CorsErrorResponseException(context.getCors(),
                "server_error",
                "PIC Trust Plane URL is not configured for this realm",
                Response.Status.INTERNAL_SERVER_ERROR);
        }

        // Step 2: Validate subject token and get the user session
        String subjectToken = context.getParams().getSubjectToken();
        if (subjectToken == null || subjectToken.isBlank()) {
            throw new CorsErrorResponseException(context.getCors(),
                "invalid_request",
                "subject_token is required for PIC token exchange",
                Response.Status.BAD_REQUEST);
        }

        // Decode and validate the subject token using Keycloak's token verification
        AccessToken accessToken;
        UserSessionModel userSession;
        UserModel user;
        try {
            accessToken = validateSubjectToken(context, subjectToken);
            userSession = findUserSession(context, accessToken);
            user = userSession.getUser();
        } catch (CorsErrorResponseException e) {
            throw e;
        } catch (Exception e) {
            LOG.warnv(e, "Failed to validate subject token in realm {0}", realm.getName());
            throw new CorsErrorResponseException(context.getCors(),
                "invalid_grant",
                "Subject token validation failed",
                Response.Status.BAD_REQUEST);
        }

        // Step 3: Extract p_0 (origin principal)
        // Create PrincipalExtractor with the realm's configured max act depth
        PrincipalExtractor principalExtractor = new PrincipalExtractor(realmConfig.getMaxActDepth());
        PrincipalExtractor.PrincipalInfo principalInfo;
        try {
            Map<String, Object> claims = extractClaimsMap(accessToken);
            // Fallback: if the decoded token has no sub, use the authenticated user's ID.
            // This handles cases where session.tokens().decode() doesn't populate
            // the subject field (e.g., Keycloak 26 internal token representation).
            if (!claims.containsKey("sub") && user != null) {
                claims.put("sub", user.getId());
            }
            String issuer = accessToken.getIssuer() != null
                ? accessToken.getIssuer()
                : realm.getAttributes().get("issuer");
            if (issuer == null) {
                issuer = getRealmIssuer(realm);
            }
            principalInfo = principalExtractor.extractPrincipal(claims, issuer);
        } catch (PicExchangeException e) {
            LOG.warnv("Principal extraction failed: {0}", e.getMessage());
            throw new CorsErrorResponseException(context.getCors(),
                e.getOauthError(),
                e.getMessage(),
                Response.Status.BAD_REQUEST);
        }

        LOG.infov("PIC exchange: p_0={0} for user {1} via client {2}",
            principalInfo.principalId(), user.getUsername(), client.getClientId());

        // Step 4: Compute effective PIC operations
        List<String> userOps = loadUserOps(user, realmConfig);
        String requestedScope = context.getParams().getScope();
        List<String> requestedOps = (requestedScope != null && !requestedScope.isBlank())
            ? opsResolver.parseScopeString(requestedScope)
            : null;
        List<String> effectiveOps = opsResolver.intersectOps(userOps, requestedOps);

        if (effectiveOps.isEmpty()) {
            LOG.warnv("No valid PIC operations for user {0}: authorized={1}, requested={2}",
                user.getUsername(), userOps, requestedOps);
            throw new CorsErrorResponseException(context.getCors(),
                "access_denied",
                "No valid PIC operations: user has no authorized operations"
                    + " matching the requested scope",
                Response.Status.FORBIDDEN);
        }

        LOG.debugv("PIC ops resolved: effective={0} (authorized={1}, requested={2})",
            effectiveOps, userOps, requestedOps);

        // Step 5: Call Trust Plane to issue or process PCA
        String executorName = client.getAttribute(PicConstants.CLIENT_ATTR_PIC_EXECUTOR_NAME);
        if (executorName == null || executorName.isBlank()) {
            executorName = client.getClientId();
        }

        Map<String, String> executorBinding = new LinkedHashMap<>();
        executorBinding.put("service", executorName);
        executorBinding.put("realm", realm.getName());
        executorBinding.put("client_id", client.getClientId());

        // Detect multi-hop: if the subject token is itself a PIC token,
        // extract the predecessor PCA and call processPoc() instead of issuePca()
        String predecessorPca = extractPredecessorPca(accessToken);

        PcaIssuanceResult pcaResult;
        try {
            if (predecessorPca != null) {
                // Multi-hop successor: process PoC with predecessor PCA
                LOG.infov("Multi-hop PIC exchange detected: processing PoC for successor PCA");
                pcaResult = trustPlaneClient.processPoc(
                    realmConfig, predecessorPca, effectiveOps, executorBinding);
            } else {
                // Initial hop (hop 0): issue PCA_0
                pcaResult = trustPlaneClient.issuePca(
                    realmConfig, subjectToken, "jwt", effectiveOps, executorBinding);
            }
        } catch (TrustPlaneException e) {
            // handleTrustPlaneError either returns null (fail-open) or throws (fail-closed).
            handleTrustPlaneError(context, realmConfig, e);
            // If we reach here, fail-open mode: issue a standard token without PIC claims
            return buildFailOpenTokenResponse(context, realm, accessToken, realmConfig);
        }

        LOG.infov("PCA issued: hop={0}, p_0={1}, ops={2}, cat_kid={3}",
            pcaResult.getHop(), pcaResult.getP0(), pcaResult.getOps(), extractCatKid(pcaResult));

        // Step 6: Build PIC-enhanced JWT response
        return buildPicTokenResponse(context, realm, client, user, accessToken,
            principalInfo, pcaResult, effectiveOps, executorName, realmConfig);
    }

    @Override
    public void close() {
        // Per-request cleanup — nothing to clean up.
        // TrustPlaneClient is managed by the factory, not per-request.
    }

    // =========================================================================
    // Subject Token Validation
    // =========================================================================

    /**
     * Validates the subject token using Keycloak's built-in token verification.
     *
     * @return the decoded AccessToken
     */
    AccessToken validateSubjectToken(TokenExchangeContext context, String subjectToken) {
        try {
            AccessToken token = session.tokens().decode(subjectToken, AccessToken.class);
            if (token == null) {
                throw new CorsErrorResponseException(context.getCors(),
                    "invalid_grant",
                    "Invalid subject token: token could not be decoded or verified",
                    Response.Status.BAD_REQUEST);
            }
            return token;
        } catch (CorsErrorResponseException e) {
            throw e;
        } catch (Exception e) {
            LOG.debugv("Subject token validation failed: {0}", e.getMessage());
            throw new CorsErrorResponseException(context.getCors(),
                "invalid_grant",
                "Invalid subject token: token could not be decoded or verified",
                Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Finds the user session for the given access token.
     */
    UserSessionModel findUserSession(TokenExchangeContext context, AccessToken accessToken) {
        RealmModel realm = context.getRealm();
        String sessionId = accessToken.getSessionId();

        if (sessionId != null) {
            UserSessionModel userSession = session.sessions().getUserSession(realm, sessionId);
            if (userSession != null) {
                return userSession;
            }
        }

        // Fallback: look up user by subject
        String subject = accessToken.getSubject();
        if (subject != null) {
            UserModel user = session.users().getUserById(realm, subject);
            if (user == null) {
                user = session.users().getUserByUsername(realm, subject);
            }
            if (user != null) {
                // Create a transient session for the exchange
                UserSessionModel userSession = session.sessions().createUserSession(
                    null, realm, user, user.getUsername(),
                    context.getClientConnection().getRemoteAddr(),
                    "token-exchange", false, null, null,
                    UserSessionModel.SessionPersistenceState.TRANSIENT);
                return userSession;
            }
        }

        throw new CorsErrorResponseException(context.getCors(),
            "invalid_grant",
            "Could not find user session for subject token",
            Response.Status.BAD_REQUEST);
    }

    // =========================================================================
    // Claims Extraction
    // =========================================================================

    /**
     * Extracts a claims map from an AccessToken for use with PrincipalExtractor.
     *
     * <p>This method handles both the typed AccessToken fields and the otherClaims
     * map because Keycloak's {@code session.tokens().decode()} may not populate
     * all typed fields (e.g., {@code getSubject()} may return null even when the
     * JWT contains a {@code sub} claim). The method checks both sources.
     */
    @SuppressWarnings("unchecked")
    Map<String, Object> extractClaimsMap(AccessToken accessToken) {
        Map<String, Object> claims = new HashMap<>();

        // Extract standard claims from typed fields
        if (accessToken.getSubject() != null) {
            claims.put("sub", accessToken.getSubject());
        }
        if (accessToken.getIssuer() != null) {
            claims.put("iss", accessToken.getIssuer());
        }
        if (accessToken.getPreferredUsername() != null) {
            claims.put("preferred_username", accessToken.getPreferredUsername());
        }

        // Also check otherClaims for standard fields that may not be populated
        // in the typed getters (Keycloak's decode() sometimes puts them here)
        Map<String, Object> otherClaims = accessToken.getOtherClaims();
        if (otherClaims != null) {
            // sub may be in otherClaims if decode() didn't populate getSubject()
            if (!claims.containsKey("sub") && otherClaims.containsKey("sub")) {
                Object sub = otherClaims.get("sub");
                if (sub instanceof String) {
                    claims.put("sub", sub);
                }
            }
            // iss may be in otherClaims
            if (!claims.containsKey("iss") && otherClaims.containsKey("iss")) {
                Object iss = otherClaims.get("iss");
                if (iss instanceof String) {
                    claims.put("iss", iss);
                }
            }

            // Extract act claim
            Object actClaim = otherClaims.get("act");
            if (actClaim != null) {
                claims.put("act", actClaim);
            }
        }

        return claims;
    }

    // =========================================================================
    // User Operations Loading
    // =========================================================================

    /**
     * Loads the user's authorized PIC operations from user attributes.
     */
    List<String> loadUserOps(UserModel user, PicRealmConfig realmConfig) {
        String attrName = realmConfig.getOpsUserAttribute();
        List<String> attrValues = user.getAttributeStream(attrName).toList();
        List<String> ops = opsResolver.parseUserOps(attrValues);

        if (ops.isEmpty()) {
            LOG.debugv("No PIC ops found in user attribute '{0}' for user {1}",
                attrName, user.getUsername());
        }

        return ops;
    }

    // =========================================================================
    // Trust Plane Error Handling
    // =========================================================================

    /**
     * Handles Trust Plane communication errors.
     *
     * <p>For transient errors (UNREACHABLE, TIMEOUT), respects the realm's
     * fail-open setting. For security-critical errors (REJECTED,
     * MONOTONICITY_VIOLATION), always fails.
     *
     * @throws CorsErrorResponseException for fail-closed or non-transient errors.
     *         Returns normally (no exception) only when fail-open is enabled
     *         and the error is transient — caller should then issue a standard
     *         non-PIC token.
     */
    void handleTrustPlaneError(TokenExchangeContext context,
                               PicRealmConfig realmConfig,
                               TrustPlaneException e) {
        LOG.errorv(e, "Trust Plane error during PIC exchange: type={0}, http={1}",
            e.getFailureType(), e.getHttpStatus());

        // Security-critical failures always fail (never fail-open)
        if (!e.isTransient()) {
            Response.Status status = switch (e.getFailureType()) {
                case MONOTONICITY_VIOLATION -> Response.Status.FORBIDDEN;
                case REJECTED -> mapHttpStatus(e.getHttpStatus());
                case INVALID_RESPONSE -> Response.Status.BAD_GATEWAY;
                default -> Response.Status.INTERNAL_SERVER_ERROR;
            };

            throw new CorsErrorResponseException(context.getCors(),
                mapToOAuthError(e),
                "Trust Plane error: " + e.getMessage(),
                status);
        }

        // Transient failure — check fail-open setting
        if (realmConfig.isFailOpen()) {
            LOG.warnv("SECURITY WARNING: Trust Plane unreachable, failing OPEN for realm. "
                + "PIC guarantees are NOT enforced. Issuing standard token without PIC claims. "
                + "Error: {0}", e.getMessage());
            return; // Caller issues a standard non-PIC token
        }

        // Fail closed (default, secure behavior)
        Response.Status status = (e.getFailureType() == TrustPlaneException.FailureType.TIMEOUT)
            ? Response.Status.GATEWAY_TIMEOUT
            : Response.Status.SERVICE_UNAVAILABLE;

        throw new CorsErrorResponseException(context.getCors(),
            "temporarily_unavailable",
            "Trust Plane is unreachable: " + e.getMessage(),
            status);
    }

    // =========================================================================
    // PIC Token Response Building
    // =========================================================================

    /**
     * Builds the PIC-enhanced JWT token response.
     *
     * <p>The response follows the OAuth 2.0 Token Exchange (RFC 8693) format:
     * <pre>{@code
     * {
     *   "access_token": "<PIC JWT>",
     *   "issued_token_type": "urn:ietf:params:oauth:token-type:pic_token",
     *   "token_type": "N_A",
     *   "expires_in": 300
     * }
     * }</pre>
     */
    Response buildPicTokenResponse(TokenExchangeContext context,
                                   RealmModel realm, ClientModel client,
                                   UserModel user,
                                   AccessToken subjectAccessToken,
                                   PrincipalExtractor.PrincipalInfo principalInfo,
                                   PcaIssuanceResult pcaResult,
                                   List<String> effectiveOps,
                                   String executorName,
                                   PicRealmConfig realmConfig) {

        // Build the PIC-enhanced access token
        AccessToken picToken = new AccessToken();

        // Standard JWT claims
        picToken.id(UUID.randomUUID().toString());
        picToken.issuer(getRealmIssuer(realm));
        // Use subject from access token, falling back to user ID if decode() didn't populate sub
        String subject = subjectAccessToken.getSubject();
        if (subject == null && user != null) {
            subject = user.getId();
        }
        picToken.subject(subject);
        picToken.type(PicConstants.PIC_JWT_TYPE);

        // Audience from the exchange request, or from the subject token
        String audience = context.getParams().getAudience();
        if (audience != null && !audience.isBlank()) {
            picToken.audience(audience);
        } else if (subjectAccessToken.getAudience() != null) {
            for (String aud : subjectAccessToken.getAudience()) {
                picToken.audience(aud);
            }
        }

        // Token lifetime
        long now = System.currentTimeMillis() / 1000;
        int lifetimeSeconds = realmConfig.getTokenLifetimeSeconds();
        picToken.iat(now);
        picToken.exp(now + lifetimeSeconds);

        // Preserve the act claim chain from the subject token
        Map<String, Object> subjectOtherClaims = subjectAccessToken.getOtherClaims();
        if (subjectOtherClaims != null && subjectOtherClaims.containsKey("act")) {
            picToken.setOtherClaims("act", subjectOtherClaims.get("act"));
        } else {
            // If no act chain exists, the subject IS the original user,
            // so we don't need an act claim
        }

        // PIC-specific claims: pic_provenance
        PicProvenanceClaim provenance = new PicProvenanceClaim(
            principalInfo.type(),
            principalInfo.principalId(),
            pcaResult.pcaHash(),
            extractCatKid(pcaResult),
            pcaResult.getHop(),
            realmConfig.getTrustPlaneUrl()
        );
        picToken.setOtherClaims(PicConstants.CLAIM_PIC_PROVENANCE, provenance.toClaimMap());

        // PIC-specific claims: pic_ops
        picToken.setOtherClaims(PicConstants.CLAIM_PIC_OPS, effectiveOps);

        // PIC-specific claims: pic_chain
        // For multi-hop, preserve predecessor chain entries from the subject token
        List<Map<String, Object>> chain = new ArrayList<>();
        if (subjectOtherClaims != null) {
            Object predecessorChain = subjectOtherClaims.get(PicConstants.CLAIM_PIC_CHAIN);
            if (predecessorChain instanceof List<?> predecessorList) {
                for (Object entry : predecessorList) {
                    if (entry instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> entryMap = (Map<String, Object>) entry;
                        chain.add(entryMap);
                    }
                }
            }
        }
        PicChainEntry chainEntry = new PicChainEntry(
            pcaResult.getHop(),
            executorName,
            effectiveOps,
            pcaResult.pcaHash(),
            extractCatKid(pcaResult)
        );
        chain.add(chainEntry.toClaimMap());
        picToken.setOtherClaims(PicConstants.CLAIM_PIC_CHAIN, chain);

        // Sign the token using Keycloak's realm signing key with custom JOSE header typ.
        // We use JWSBuilder directly instead of session.tokens().encode() because
        // the default encoder hardcodes the JWT header typ to "JWT", but the PIC spec
        // requires "pic+jwt" in the JOSE header to distinguish PIC tokens from standard JWTs.
        String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.ACCESS);
        SignatureProvider signatureProvider =
            session.getProvider(SignatureProvider.class, signatureAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer();
        String encodedToken = new JWSBuilder()
            .type(PicConstants.PIC_JWT_TYPE)
            .jsonContent(picToken)
            .sign(signer);

        // Build the OAuth 2.0 Token Exchange response
        AccessTokenResponse response = new AccessTokenResponse();
        response.setToken(encodedToken);
        response.setTokenType("N_A");
        response.setExpiresIn(lifetimeSeconds);
        response.setOtherClaims(OAuth2Constants.ISSUED_TOKEN_TYPE, PicConstants.PIC_TOKEN_TYPE);

        // Scope: the effective PIC operations as space-delimited string
        response.setOtherClaims(OAuth2Constants.SCOPE, String.join(" ", effectiveOps));

        // No refresh token — PIC tokens are short-lived, re-exchange required
        response.setRefreshToken(null);

        LOG.infov("PIC token issued: p_0={0}, hop={1}, ops_count={2}, expires_in={3}s",
            principalInfo.principalId(), pcaResult.getHop(),
            effectiveOps.size(), lifetimeSeconds);

        return context.getCors().add(
            Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
    }

    /**
     * Builds a standard (non-PIC) token response for fail-open mode.
     *
     * <p>When the Trust Plane is unreachable and {@code pic_fail_open=true},
     * this method issues a standard access token WITHOUT PIC claims.
     * This defeats PIC's security guarantees and should only be used
     * for development/debugging.
     *
     * <p>SECURITY WARNING: Tokens issued in fail-open mode carry no
     * provenance authority and cannot be verified by downstream services.
     */
    Response buildFailOpenTokenResponse(TokenExchangeContext context,
                                         RealmModel realm,
                                         AccessToken subjectAccessToken,
                                         PicRealmConfig realmConfig) {

        AccessToken standardToken = new AccessToken();
        standardToken.id(UUID.randomUUID().toString());
        standardToken.issuer(getRealmIssuer(realm));
        // Use same null-fallback pattern as buildPicTokenResponse
        String subject = subjectAccessToken.getSubject();
        if (subject == null) {
            Map<String, Object> otherClaims = subjectAccessToken.getOtherClaims();
            if (otherClaims != null && otherClaims.get("sub") instanceof String sub) {
                subject = sub;
            }
        }
        standardToken.subject(subject);

        long now = System.currentTimeMillis() / 1000;
        int lifetimeSeconds = realmConfig.getTokenLifetimeSeconds();
        standardToken.iat(now);
        standardToken.exp(now + lifetimeSeconds);

        // Preserve audience from subject token
        if (subjectAccessToken.getAudience() != null) {
            for (String aud : subjectAccessToken.getAudience()) {
                standardToken.audience(aud);
            }
        }

        String encodedToken = session.tokens().encode(standardToken);

        AccessTokenResponse response = new AccessTokenResponse();
        response.setToken(encodedToken);
        response.setTokenType("Bearer");
        response.setExpiresIn(lifetimeSeconds);
        response.setOtherClaims(OAuth2Constants.ISSUED_TOKEN_TYPE,
            "urn:ietf:params:oauth:token-type:access_token");
        response.setRefreshToken(null);

        LOG.warnv("FAIL-OPEN: Standard token issued without PIC claims for sub={0}, expires_in={1}s",
            subjectAccessToken.getSubject(), lifetimeSeconds);

        return context.getCors().add(
            Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /**
     * Gets the realm issuer URL in the standard Keycloak format.
     */
    String getRealmIssuer(RealmModel realm) {
        // Keycloak standard issuer format
        String frontendUrl = session.getContext().getUri().getBaseUri().toString();
        if (frontendUrl.endsWith("/")) {
            frontendUrl = frontendUrl.substring(0, frontendUrl.length() - 1);
        }
        return frontendUrl + "/realms/" + realm.getName();
    }

    /**
     * Extracts the predecessor PCA from a subject token if it is a PIC token.
     *
     * <p>A subject token is a PIC token if it contains a {@code pic_provenance}
     * claim (set by a previous PIC exchange). The predecessor PCA is needed
     * by the Trust Plane to verify the chain and issue a successor PCA.
     *
     * <p>The PCA is extracted from the {@code pic_chain} claim. The last entry
     * in the chain contains the most recent PCA hash. However, the actual PCA
     * bytes are not stored in the JWT — they must be retrieved from the subject
     * token's associated data. For the Trust Plane's {@code processPoc} endpoint,
     * we pass the Base64-encoded PCA from the chain entry's pca_hash as a reference.
     *
     * @param accessToken the decoded subject token
     * @return the predecessor PCA (Base64) if this is a PIC token, or null for initial exchanges
     */
    @SuppressWarnings("unchecked")
    String extractPredecessorPca(AccessToken accessToken) {
        Map<String, Object> otherClaims = accessToken.getOtherClaims();
        if (otherClaims == null) {
            return null;
        }

        // Check if this token has pic_provenance (i.e., it's a PIC token)
        Object provenanceObj = otherClaims.get(PicConstants.CLAIM_PIC_PROVENANCE);
        if (!(provenanceObj instanceof Map)) {
            return null;
        }

        // Extract the PCA hash from pic_provenance.pca_0_hash
        // This serves as a reference to the predecessor PCA for the Trust Plane
        Map<String, Object> provenance = (Map<String, Object>) provenanceObj;
        Object pcaHashObj = provenance.get(PicConstants.PROV_PCA_HASH);
        if (pcaHashObj instanceof String pcaHash && !pcaHash.isBlank()) {
            return pcaHash;
        }

        return null;
    }

    /**
     * Extracts the CAT kid from a PCA issuance result.
     *
     * <p>Uses the {@code cat_kid} field returned by the Trust Plane API,
     * which identifies the key that signed the PCA. Falls back to a
     * truncated PCA hash if the Trust Plane does not return a cat_kid.
     */
    private String extractCatKid(PcaIssuanceResult pcaResult) {
        String catKid = pcaResult.getCatKid();
        if (catKid != null && !catKid.isBlank()) {
            return catKid;
        }
        // Fallback for older Trust Plane versions that don't return cat_kid
        return pcaResult.pcaHash().substring(0, Math.min(16, pcaResult.pcaHash().length()));
    }

    /**
     * Maps a Trust Plane HTTP status to a JAX-RS Response status.
     */
    private Response.Status mapHttpStatus(int httpStatus) {
        return switch (httpStatus) {
            case 400 -> Response.Status.BAD_REQUEST;
            case 401 -> Response.Status.UNAUTHORIZED;
            case 403 -> Response.Status.FORBIDDEN;
            case 404 -> Response.Status.NOT_FOUND;
            default -> Response.Status.INTERNAL_SERVER_ERROR;
        };
    }

    /**
     * Maps a Trust Plane exception to an OAuth error code.
     */
    private String mapToOAuthError(TrustPlaneException e) {
        return switch (e.getFailureType()) {
            case MONOTONICITY_VIOLATION -> "access_denied";
            case REJECTED -> "access_denied";
            case INVALID_RESPONSE -> "server_error";
            case UNREACHABLE, TIMEOUT -> "temporarily_unavailable";
        };
    }
}

package com.provenance.keycloak.pic.exchange;

import com.provenance.keycloak.pic.PicConstants;

import java.util.Map;

/**
 * Extracts the origin principal (p_0) from JWT claims.
 *
 * <p>For token exchange tokens with an {@code act} claim (RFC 8693 Section 4.1),
 * traverses to the deepest {@code act.sub} to find the original human user.
 * This matches the algorithm in
 * {@code provenance-bridge/src/handlers/jwt.rs:deepest_act_subject_recursive}.
 *
 * <p>Example traversal:
 * <pre>
 * { "sub": "service-B", "act": { "sub": "service-A", "act": { "sub": "alice" } } }
 * → returns "alice"
 * </pre>
 *
 * <p>The extraction result is a {@link PrincipalInfo} containing:
 * <ul>
 *   <li>{@code subject} — the raw subject string (e.g., "alice")</li>
 *   <li>{@code principalId} — the formatted PIC principal identifier
 *       (e.g., "oidc:https://keycloak.example.com/realms/pic-demo#alice")</li>
 *   <li>{@code type} — always "oidc" for JWT-sourced principals</li>
 * </ul>
 */
public class PrincipalExtractor {

    private final int maxActDepth;

    /**
     * Creates a PrincipalExtractor with the default maximum act chain depth.
     */
    public PrincipalExtractor() {
        this(PicConstants.DEFAULT_MAX_ACT_DEPTH);
    }

    /**
     * Creates a PrincipalExtractor with a custom maximum act chain depth.
     *
     * @param maxActDepth maximum allowed nesting depth for the act claim chain.
     *                    Must be positive. Tokens exceeding this depth are rejected
     *                    to prevent stack overflow from malicious tokens.
     */
    public PrincipalExtractor(int maxActDepth) {
        if (maxActDepth <= 0) {
            throw new IllegalArgumentException("maxActDepth must be positive, got: " + maxActDepth);
        }
        this.maxActDepth = maxActDepth;
    }

    /**
     * Extract the origin principal from token claims.
     *
     * <p>Algorithm:
     * <ol>
     *   <li>If an {@code act} claim exists, traverse to the deepest {@code act.sub}
     *       to find the original human user (PROVENANCE invariant).</li>
     *   <li>If no {@code act} claim, use the top-level {@code sub} claim.</li>
     *   <li>Format as PIC principal identifier: {@code oidc:{issuer}#{subject}}</li>
     * </ol>
     *
     * @param claims the JWT claims as a map (top-level keys to values)
     * @param issuer the token issuer ({@code iss} claim value)
     * @return PrincipalInfo containing the extracted p_0
     * @throws PicExchangeException if no principal can be extracted
     */
    @SuppressWarnings("unchecked")
    public PrincipalInfo extractPrincipal(Map<String, Object> claims, String issuer)
            throws PicExchangeException {

        String subject = null;

        // Step 1: Check for act claim (RFC 8693 Section 4.1)
        Object actValue = claims.get("act");
        if (actValue instanceof Map) {
            subject = deepestActSubject((Map<String, Object>) actValue, 0);
        }

        // Step 2: Fallback to top-level sub
        if (subject == null) {
            Object subValue = claims.get("sub");
            if (subValue instanceof String) {
                subject = (String) subValue;
            }
        }

        // Step 3: Validate we have a subject
        if (subject == null || subject.isBlank()) {
            throw new PicExchangeException(
                PicExchangeException.ErrorCode.MISSING_PRINCIPAL,
                "No principal could be extracted: no 'act.sub' chain or top-level 'sub' claim found"
            );
        }

        // Step 4: Build principal identifier
        String principalId = String.format(PicConstants.PRINCIPAL_FORMAT_OIDC, issuer, subject);

        return new PrincipalInfo(subject, principalId, PicConstants.PRINCIPAL_TYPE_OIDC);
    }

    /**
     * Recursively traverse the act claim chain to find the deepest subject.
     *
     * <p>Given: {@code { "sub": "service-A", "act": { "sub": "alice" } }}
     * <br>Returns: {@code "alice"} (the deepest/original subject)
     *
     * <p>SECURITY: This method is bounded by {@link #maxActDepth} to prevent
     * stack overflow attacks from maliciously nested act chains.
     *
     * @param actClaim the act claim as a map
     * @param depth current recursion depth (starts at 0)
     * @return the deepest subject string, or {@code null} if none found
     * @throws PicExchangeException if the chain exceeds maximum depth
     */
    @SuppressWarnings("unchecked")
    String deepestActSubject(Map<String, Object> actClaim, int depth)
            throws PicExchangeException {

        if (depth >= maxActDepth) {
            throw new PicExchangeException(
                PicExchangeException.ErrorCode.ACT_CHAIN_TOO_DEEP,
                "Act claim chain exceeds maximum depth of " + maxActDepth
                    + ". This may indicate a malicious token."
            );
        }

        // If there's a nested act, go deeper first (depth-first traversal)
        Object nestedAct = actClaim.get("act");
        if (nestedAct instanceof Map) {
            String deeper = deepestActSubject((Map<String, Object>) nestedAct, depth + 1);
            if (deeper != null) {
                return deeper;
            }
        }

        // Return this level's sub
        Object subValue = actClaim.get("sub");
        if (subValue instanceof String) {
            String sub = (String) subValue;
            if (!sub.isBlank()) {
                return sub;
            }
        }

        return null;
    }

    /**
     * Information about an extracted principal.
     *
     * @param subject the raw subject string (e.g., "alice-user-id")
     * @param principalId the formatted PIC principal identifier
     *                    (e.g., "oidc:https://keycloak.example.com/realms/pic-demo#alice-user-id")
     * @param type the principal type (e.g., "oidc")
     */
    public record PrincipalInfo(String subject, String principalId, String type) {
    }
}

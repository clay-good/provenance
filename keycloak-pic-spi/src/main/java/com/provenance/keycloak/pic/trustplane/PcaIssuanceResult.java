package com.provenance.keycloak.pic.trustplane;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Result of a PCA issuance from the Trust Plane.
 *
 * <p>This DTO maps to the JSON response from both:
 * <ul>
 *   <li>{@code POST /v1/pca/issue} → {@code IssuePcaResponse} in Rust</li>
 *   <li>{@code POST /v1/poc/process} → {@code ProcessPocResponse} in Rust</li>
 * </ul>
 *
 * <p>Both endpoints return the same structure:
 * <pre>{@code
 * {
 *   "pca": "<base64 COSE_Sign1 bytes>",
 *   "hop": 0,
 *   "p_0": "oidc:issuer#subject",
 *   "ops": ["read:claims:alice/*"],
 *   "exp": "2026-02-12T15:00:00Z"       // optional
 * }
 * }</pre>
 *
 * <p>The {@link #pcaHash()} method computes the Base64url-encoded SHA-256
 * hash of the decoded PCA bytes, which is embedded in the JWT
 * {@code pic_provenance.pca_0_hash} claim.
 */
public class PcaIssuanceResult {

    private final String pca;
    private final int hop;
    private final String p0;
    private final List<String> ops;
    private final String catKid;
    private final String exp;

    /**
     * Creates a PCA issuance result.
     *
     * @param pca    Base64-encoded COSE_Sign1 PCA bytes
     * @param hop    hop number (0 for PCA_0, incremented for successors)
     * @param p0     origin principal identifier (e.g., "oidc:issuer#subject")
     * @param ops    effective operations granted by the Trust Plane
     * @param catKid Trust Plane key ID (CAT kid) that signed the PCA
     * @param exp    PCA expiration in ISO 8601 / RFC 3339 format, or null
     */
    public PcaIssuanceResult(String pca, int hop, String p0,
                             List<String> ops, String catKid, String exp) {
        this.pca = pca;
        this.hop = hop;
        this.p0 = p0;
        this.ops = ops != null ? Collections.unmodifiableList(ops) : Collections.emptyList();
        this.catKid = catKid;
        this.exp = exp;
    }

    /**
     * Returns the Base64-encoded COSE_Sign1 PCA bytes.
     *
     * <p>This is the opaque signed PCA that should be stored in the
     * PIC token's {@code pic_chain} for chain verification, and sent
     * to the Trust Plane as the predecessor in subsequent PoC requests.
     *
     * @return Base64-encoded PCA
     */
    public String getPca() {
        return pca;
    }

    /**
     * Returns the hop number.
     *
     * <p>0 for PCA_0 (initial issuance at federation entry),
     * incremented by 1 for each successor PCA.
     *
     * @return hop number
     */
    public int getHop() {
        return hop;
    }

    /**
     * Returns the origin principal (p_0).
     *
     * <p>Format: {@code "oidc:{issuer}#{subject}"} for OIDC principals.
     * This value is IMMUTABLE — it is always the same as the original
     * PCA_0's p_0, enforced by the Trust Plane.
     *
     * @return the origin principal identifier
     */
    public String getP0() {
        return p0;
    }

    /**
     * Returns the effective operations granted by the Trust Plane.
     *
     * <p>For PCA_0, these are the intersection of the credential's
     * authorized ops and the requested ops. For successor PCAs,
     * these are guaranteed to be a subset of the predecessor's ops
     * (monotonicity invariant enforced by the Trust Plane).
     *
     * @return unmodifiable list of granted operations
     */
    public List<String> getOps() {
        return ops;
    }

    /**
     * Returns the Trust Plane key ID (CAT kid) that signed the PCA.
     *
     * @return the CAT kid, or null if not provided
     */
    public String getCatKid() {
        return catKid;
    }

    /**
     * Returns the PCA expiration time.
     *
     * @return expiration in ISO 8601 / RFC 3339 format, or null if unbounded
     */
    public String getExp() {
        return exp;
    }

    /**
     * Computes the Base64url-encoded SHA-256 hash of the PCA bytes.
     *
     * <p>This hash is embedded in the JWT's {@code pic_provenance.pca_0_hash}
     * claim to cryptographically bind the JWT to the PCA without embedding
     * the full COSE_Sign1 structure in the JWT.
     *
     * <p>Algorithm: {@code Base64url_no_pad(SHA-256(Base64_decode(pca)))}
     *
     * @return Base64url-encoded (no padding) SHA-256 hash of the PCA bytes
     * @throws IllegalStateException if SHA-256 is not available (should never happen on compliant JVMs)
     */
    public String pcaHash() {
        if (pca == null || pca.isEmpty()) {
            throw new IllegalStateException("Cannot compute PCA hash: PCA bytes are null or empty");
        }
        try {
            byte[] pcaBytes = Base64.getDecoder().decode(pca);
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(pcaBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Cannot compute PCA hash: invalid Base64 encoding", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public String toString() {
        return "PcaIssuanceResult{" +
            "hop=" + hop +
            ", p0='" + p0 + '\'' +
            ", ops=" + ops +
            ", catKid='" + catKid + '\'' +
            ", exp='" + exp + '\'' +
            '}';
    }
}

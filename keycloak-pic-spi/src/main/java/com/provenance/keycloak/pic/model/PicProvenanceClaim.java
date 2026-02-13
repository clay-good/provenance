package com.provenance.keycloak.pic.model;

import com.provenance.keycloak.pic.PicConstants;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Model for the {@code pic_provenance} JWT claim.
 *
 * <p>This claim anchors the PIC token to the Trust Plane by recording:
 * <ul>
 *   <li>The PIC version</li>
 *   <li>The origin principal (p_0) — immutable throughout the chain</li>
 *   <li>A SHA-256 hash of the PCA_0 COSE_Sign1 bytes</li>
 *   <li>The Trust Plane key ID that signed the PCA</li>
 *   <li>The current hop number</li>
 *   <li>The Trust Plane URL for verification</li>
 * </ul>
 *
 * <p>Example JSON:
 * <pre>
 * {
 *   "version": "1.0",
 *   "p_0": { "type": "oidc", "value": "oidc:issuer#alice" },
 *   "pca_0_hash": "base64url(SHA-256(...))",
 *   "cat_kid": "trust-plane-key-id",
 *   "hop": 0,
 *   "trust_plane": "https://trust-plane.example.com"
 * }
 * </pre>
 */
public class PicProvenanceClaim {

    private final String version;
    private final String p0Type;
    private final String p0Value;
    private final String pca0Hash;
    private final String catKid;
    private final int hop;
    private final String trustPlane;

    /**
     * Creates a PIC provenance claim.
     *
     * @param p0Type principal type (e.g., "oidc")
     * @param p0Value principal identifier (e.g., "oidc:issuer#alice")
     * @param pca0Hash base64url-encoded SHA-256 hash of PCA_0 COSE_Sign1 bytes
     * @param catKid Trust Plane key ID that signed the PCA
     * @param hop current hop number (0 for initial issuance)
     * @param trustPlane Trust Plane URL (may be null)
     */
    public PicProvenanceClaim(String p0Type, String p0Value, String pca0Hash,
                               String catKid, int hop, String trustPlane) {
        this.version = PicConstants.PIC_VERSION;
        this.p0Type = p0Type;
        this.p0Value = p0Value;
        this.pca0Hash = pca0Hash;
        this.catKid = catKid;
        this.hop = hop;
        this.trustPlane = trustPlane;
    }

    /**
     * Converts this claim to a map suitable for embedding in a JWT.
     *
     * @return ordered map representation of the claim
     */
    public Map<String, Object> toClaimMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(PicConstants.PROV_VERSION, version);

        Map<String, String> p0Map = new LinkedHashMap<>();
        p0Map.put("type", p0Type);
        p0Map.put("value", p0Value);
        map.put(PicConstants.PROV_P0, p0Map);

        map.put(PicConstants.PROV_PCA_HASH, pca0Hash);
        map.put(PicConstants.PROV_CAT_KID, catKid);
        map.put(PicConstants.PROV_HOP, hop);

        if (trustPlane != null) {
            map.put(PicConstants.PROV_TRUST_PLANE, trustPlane);
        }

        return map;
    }

    /**
     * Creates a PicProvenanceClaim from a JWT claim map.
     *
     * @param claimMap the claim map from a decoded JWT
     * @return the parsed PicProvenanceClaim, or null if the map is invalid
     */
    @SuppressWarnings("unchecked")
    public static PicProvenanceClaim fromClaimMap(Map<String, Object> claimMap) {
        if (claimMap == null) {
            return null;
        }

        Object p0Obj = claimMap.get(PicConstants.PROV_P0);
        if (!(p0Obj instanceof Map)) {
            return null;
        }
        Map<String, Object> p0Map = (Map<String, Object>) p0Obj;

        String p0Type = p0Map.get("type") instanceof String ? (String) p0Map.get("type") : null;
        String p0Value = p0Map.get("value") instanceof String ? (String) p0Map.get("value") : null;
        String pcaHash = claimMap.get(PicConstants.PROV_PCA_HASH) instanceof String
            ? (String) claimMap.get(PicConstants.PROV_PCA_HASH) : null;
        String catKid = claimMap.get(PicConstants.PROV_CAT_KID) instanceof String
            ? (String) claimMap.get(PicConstants.PROV_CAT_KID) : null;

        int hop = 0;
        Object hopObj = claimMap.get(PicConstants.PROV_HOP);
        if (hopObj instanceof Number) {
            hop = ((Number) hopObj).intValue();
        }

        String trustPlane = claimMap.get(PicConstants.PROV_TRUST_PLANE) instanceof String
            ? (String) claimMap.get(PicConstants.PROV_TRUST_PLANE) : null;

        if (p0Type == null || p0Value == null || pcaHash == null || catKid == null) {
            return null;
        }

        return new PicProvenanceClaim(p0Type, p0Value, pcaHash, catKid, hop, trustPlane);
    }

    // =========================================================================
    // Getters
    // =========================================================================

    public String getVersion() { return version; }
    public String getP0Type() { return p0Type; }
    public String getP0Value() { return p0Value; }
    public String getPca0Hash() { return pca0Hash; }
    public String getCatKid() { return catKid; }
    public int getHop() { return hop; }
    public String getTrustPlane() { return trustPlane; }
}

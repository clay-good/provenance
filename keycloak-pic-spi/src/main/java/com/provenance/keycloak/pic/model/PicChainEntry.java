package com.provenance.keycloak.pic.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Model for a single entry in the {@code pic_chain} JWT claim array.
 *
 * <p>Each entry records one hop in the PIC provenance chain:
 * <pre>
 * {
 *   "hop": 0,
 *   "executor": "pic-gateway",
 *   "ops": ["read:claims:alice/claim-001"],
 *   "pca_hash": "base64url(SHA-256(PCA_0))",
 *   "cat_kid": "trust-plane-key-id"
 * }
 * </pre>
 *
 * <p>The chain provides an audit trail: downstream services can inspect
 * how authority was narrowed at each hop without needing to contact
 * the Trust Plane.
 */
public class PicChainEntry {

    private final int hop;
    private final String executor;
    private final List<String> ops;
    private final String pcaHash;
    private final String catKid;

    /**
     * Creates a new chain entry.
     *
     * @param hop the hop number (0 for PCA_0)
     * @param executor the executor/service name at this hop
     * @param ops the PIC operations at this hop
     * @param pcaHash base64url-encoded SHA-256 hash of the PCA at this hop
     * @param catKid Trust Plane key ID that signed the PCA at this hop
     */
    public PicChainEntry(int hop, String executor, List<String> ops,
                          String pcaHash, String catKid) {
        this.hop = hop;
        this.executor = executor;
        this.ops = ops;
        this.pcaHash = pcaHash;
        this.catKid = catKid;
    }

    /**
     * Converts this entry to a map suitable for embedding in a JWT claim.
     *
     * @return ordered map representation of the entry
     */
    public Map<String, Object> toClaimMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("hop", hop);
        map.put("executor", executor);
        map.put("ops", ops);
        map.put("pca_hash", pcaHash);
        map.put("cat_kid", catKid);
        return map;
    }

    /**
     * Creates a PicChainEntry from a JWT claim map.
     *
     * @param claimMap the map from a decoded JWT claim array entry
     * @return the parsed PicChainEntry, or null if the map is invalid
     */
    @SuppressWarnings("unchecked")
    public static PicChainEntry fromClaimMap(Map<String, Object> claimMap) {
        if (claimMap == null) {
            return null;
        }

        int hop = 0;
        Object hopObj = claimMap.get("hop");
        if (hopObj instanceof Number) {
            hop = ((Number) hopObj).intValue();
        }

        String executor = claimMap.get("executor") instanceof String
            ? (String) claimMap.get("executor") : null;

        List<String> ops = null;
        Object opsObj = claimMap.get("ops");
        if (opsObj instanceof List) {
            ops = ((List<?>) opsObj).stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .toList();
        }

        String pcaHash = claimMap.get("pca_hash") instanceof String
            ? (String) claimMap.get("pca_hash") : null;

        String catKid = claimMap.get("cat_kid") instanceof String
            ? (String) claimMap.get("cat_kid") : null;

        if (executor == null || ops == null || pcaHash == null || catKid == null) {
            return null;
        }

        return new PicChainEntry(hop, executor, ops, pcaHash, catKid);
    }

    // =========================================================================
    // Getters
    // =========================================================================

    public int getHop() { return hop; }
    public String getExecutor() { return executor; }
    public List<String> getOps() { return ops; }
    public String getPcaHash() { return pcaHash; }
    public String getCatKid() { return catKid; }
}

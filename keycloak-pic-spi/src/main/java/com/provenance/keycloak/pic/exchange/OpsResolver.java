package com.provenance.keycloak.pic.exchange;

import com.provenance.keycloak.pic.PicConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Resolves PIC operations for a user within a realm.
 *
 * <p>Operations come from multiple sources with this priority:
 * <ol>
 *   <li>User attribute ({@code pic_ops}) — explicit PIC operations</li>
 *   <li>OAuth scopes — standard scopes as fallback</li>
 * </ol>
 *
 * <p>The resolver computes the intersection of the user's authorized ops
 * and the requested ops (from the exchange {@code scope} parameter), enforcing
 * the IDENTITY invariant (ops can only shrink).
 *
 * <p>Wildcard matching is consistent with {@code provenance-core}'s
 * {@code Pca::contains_op} and {@code provenance-plane}'s
 * {@code validation::op_is_covered}:
 * <ul>
 *   <li>{@code "*"} covers everything</li>
 *   <li>{@code "read:*"} covers {@code "read:claims:123"}</li>
 *   <li>{@code "read:claims:*"} covers {@code "read:claims:123"}</li>
 * </ul>
 */
public class OpsResolver {

    /**
     * Load a user's authorized PIC operations from a multi-valued attribute.
     *
     * <p>The attribute values can be:
     * <ul>
     *   <li>Individual operation strings: each attribute value is one operation</li>
     *   <li>A JSON array string: {@code ["read:claims:alice/*", "write:claims:alice/*"]}</li>
     *   <li>A space-delimited string: {@code "read:claims:alice/* write:claims:alice/*"}</li>
     * </ul>
     *
     * @param attributeValues the raw attribute values from the user model (may be null)
     * @return list of parsed PIC operation strings, never null
     */
    public List<String> parseUserOps(List<String> attributeValues) {
        if (attributeValues == null || attributeValues.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> ops = new ArrayList<>();
        for (String value : attributeValues) {
            if (value == null || value.isBlank()) {
                continue;
            }

            String trimmed = value.trim();

            // Check if it's a JSON array: starts with [ and ends with ]
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                parseJsonArrayOps(trimmed, ops);
            } else if (trimmed.contains(" ")) {
                // Space-delimited
                for (String op : trimmed.split("\\s+")) {
                    if (!op.isBlank()) {
                        ops.add(op);
                    }
                }
            } else {
                // Single value
                ops.add(trimmed);
            }
        }

        return ops;
    }

    /**
     * Parse a JSON array string of operations.
     *
     * <p>Handles simple JSON arrays of strings without requiring a full JSON parser.
     * Example: {@code ["read:claims:alice/*", "write:claims:alice/*"]}
     *
     * @param jsonArray the JSON array string
     * @param out list to append parsed operations to
     */
    private void parseJsonArrayOps(String jsonArray, List<String> out) {
        // Strip [ and ]
        String inner = jsonArray.substring(1, jsonArray.length() - 1).trim();
        if (inner.isEmpty()) {
            return;
        }

        // Split by comma, strip quotes
        for (String element : inner.split(",")) {
            String trimmed = element.trim();
            // Remove surrounding quotes (single or double)
            if (trimmed.length() >= 2) {
                char first = trimmed.charAt(0);
                char last = trimmed.charAt(trimmed.length() - 1);
                if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                    trimmed = trimmed.substring(1, trimmed.length() - 1);
                }
            }
            if (!trimmed.isBlank()) {
                out.add(trimmed);
            }
        }
    }

    /**
     * Compute the intersection of authorized and requested operations.
     *
     * <p>Uses wildcard-aware matching consistent with {@code provenance-core}'s
     * operation containment check ({@code Pca::contains_op}).
     *
     * <p>A requested op {@code "read:claims:alice/001"} is covered by authorized op
     * {@code "read:claims:alice/*"} because the wildcard prefix matches.
     *
     * <p>If {@code requestedOps} is null, returns all authorized ops
     * (no narrowing requested). If {@code requestedOps} is an empty list,
     * returns an empty list (explicit empty request yields empty result).
     *
     * @param authorizedOps the user's full authorized operations
     * @param requestedOps the operations requested in this exchange (null = no narrowing)
     * @return the intersection: ops that are both authorized and requested
     */
    public List<String> intersectOps(List<String> authorizedOps, List<String> requestedOps) {
        if (authorizedOps == null || authorizedOps.isEmpty()) {
            return Collections.emptyList();
        }

        // null = no narrowing requested, return all authorized ops
        if (requestedOps == null) {
            return new ArrayList<>(authorizedOps);
        }

        // Empty list = explicit empty request, return empty
        if (requestedOps.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        for (String requested : requestedOps) {
            if (requested == null || requested.isBlank()) {
                continue;
            }
            if (opIsCovered(requested, authorizedOps)) {
                result.add(requested);
            }
        }

        return result;
    }

    /**
     * Check if an operation is covered by a set of authorized operations.
     *
     * <p>This method mirrors the Rust implementation in
     * {@code provenance-plane/src/core/validation.rs::op_is_covered}:
     * <ul>
     *   <li>{@code "*"} covers everything (universal wildcard)</li>
     *   <li>Exact string match</li>
     *   <li>Wildcard prefix: {@code "read:claims:*"} covers {@code "read:claims:123"}
     *       (the prefix before {@code *} must match the start of the operation)</li>
     * </ul>
     *
     * @param op the operation to check
     * @param authorizedOps the set of authorized operations
     * @return true if the operation is covered by at least one authorized op
     */
    public boolean opIsCovered(String op, List<String> authorizedOps) {
        if (op == null || op.isBlank()) {
            return false;
        }
        for (String allowed : authorizedOps) {
            if (allowed == null) {
                continue;
            }

            // Universal wildcard covers everything
            if ("*".equals(allowed)) {
                return true;
            }

            // Exact match
            if (allowed.equals(op)) {
                return true;
            }

            // Wildcard prefix matching
            if (allowed.endsWith("*")) {
                String prefix = allowed.substring(0, allowed.length() - 1);
                if (op.startsWith(prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Parse a space-delimited scope string into individual operations.
     *
     * @param scopeString the space-delimited scope string (may be null)
     * @return list of individual scope/operation strings
     */
    public List<String> parseScopeString(String scopeString) {
        if (scopeString == null || scopeString.isBlank()) {
            return Collections.emptyList();
        }

        List<String> ops = new ArrayList<>();
        for (String part : scopeString.trim().split("\\s+")) {
            if (!part.isBlank()) {
                ops.add(part);
            }
        }
        return ops;
    }
}

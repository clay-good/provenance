package com.provenance.keycloak.pic.trustplane;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.provenance.keycloak.pic.model.PicRealmConfig;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP client for communicating with the PIC Trust Plane (Rust server).
 *
 * <p>This client implements the Trust Plane API as defined in
 * {@code provenance-plane/src/api/handlers/*.rs}. It calls:
 * <ul>
 *   <li>{@code POST /v1/pca/issue} — Issue PCA_0 at federation entry</li>
 *   <li>{@code POST /v1/poc/process} — Process PoC for successor PCA</li>
 *   <li>{@code POST /v1/keys/executor} — Register an executor key</li>
 *   <li>{@code GET /health} — Health check</li>
 * </ul>
 *
 * <p><b>Thread-safety:</b> This client is thread-safe and designed to be shared
 * across multiple Keycloak request threads. It uses {@link java.net.http.HttpClient}
 * which is thread-safe by design.
 *
 * <p><b>Connection management:</b> Uses a shared HttpClient with connection pooling.
 * Timeouts are configurable per-realm via {@link PicRealmConfig}.
 *
 * <p><b>Error handling:</b> All Trust Plane communication errors result in
 * {@link TrustPlaneException}, which the PicTokenExchangeProvider translates
 * to appropriate OAuth error responses.
 */
public class TrustPlaneClient implements AutoCloseable {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Creates a TrustPlaneClient with default settings.
     */
    public TrustPlaneClient() {
        this(HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build());
    }

    /**
     * Creates a TrustPlaneClient with a custom HttpClient.
     *
     * <p>Useful for testing or advanced configuration (custom SSL, proxy, etc.).
     *
     * @param httpClient the HTTP client to use
     */
    public TrustPlaneClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Issue a PCA_0 at federation entry.
     *
     * <p>Calls: {@code POST {trustPlaneUrl}/v1/pca/issue}
     *
     * <p>Request body matches Rust {@code IssuePcaRequest}:
     * <pre>{@code
     * {
     *   "credential": "<JWT access token>",
     *   "credential_type": "jwt",
     *   "ops": ["read:claims:alice/*"],
     *   "executor_binding": { "service": "pic-gateway", "realm": "pic-demo" }
     * }
     * }</pre>
     *
     * @param config          realm PIC configuration (provides Trust Plane URL and timeout)
     * @param credential      the subject token (JWT string)
     * @param credentialType  the credential type (e.g., "jwt")
     * @param ops             requested PIC operations
     * @param executorBinding executor metadata key-value pairs
     * @return PcaIssuanceResult containing the signed PCA and metadata
     * @throws TrustPlaneException if the Trust Plane rejects the request or is unreachable
     */
    public PcaIssuanceResult issuePca(PicRealmConfig config, String credential,
                                      String credentialType, List<String> ops,
                                      Map<String, String> executorBinding)
            throws TrustPlaneException {
        IssuePcaRequest request = new IssuePcaRequest();
        request.credential = credential;
        request.credentialType = credentialType;
        request.ops = ops;
        request.executorBinding = executorBinding != null ? executorBinding : new HashMap<>();

        String url = buildUrl(config.getTrustPlaneUrl(), "/v1/pca/issue");
        IssuePcaResponse response = post(url, request, IssuePcaResponse.class,
                                         config.getTrustPlaneTimeoutMs());

        return new PcaIssuanceResult(
            response.pca,
            response.hop,
            response.p0,
            response.ops,
            response.catKid,
            response.exp
        );
    }

    /**
     * Process a PoC (Proof of Continuity) to get a successor PCA.
     *
     * <p>Calls: {@code POST {trustPlaneUrl}/v1/poc/process}
     *
     * <p>Used when a PIC-enhanced token is exchanged again (multi-hop).
     * The predecessor PCA from the incoming token is included in the request.
     *
     * <p>Request body matches the Trust Plane API contract:
     * <pre>{@code
     * {
     *   "predecessor_pca": "<base64 COSE_Sign1 predecessor PCA>",
     *   "requested_ops": ["read:claims:alice/doc1"],
     *   "executor_binding": { "service": "...", "realm": "...", "client_id": "..." }
     * }
     * }</pre>
     *
     * @param config          realm PIC configuration
     * @param predecessorPca  Base64-encoded predecessor PCA (COSE_Sign1)
     * @param requestedOps    operations requested for the successor
     * @param executorBinding executor metadata for this hop
     * @return PcaIssuanceResult for the successor PCA
     * @throws TrustPlaneException on failure
     */
    public PcaIssuanceResult processPoc(PicRealmConfig config, String predecessorPca,
                                         List<String> requestedOps,
                                         Map<String, String> executorBinding)
            throws TrustPlaneException {
        ProcessPocRequest request = new ProcessPocRequest();
        request.predecessorPca = predecessorPca;
        request.requestedOps = requestedOps;
        request.executorBinding = executorBinding != null ? executorBinding : new HashMap<>();

        String url = buildUrl(config.getTrustPlaneUrl(), "/v1/poc/process");
        ProcessPocResponse response = post(url, request, ProcessPocResponse.class,
                                           config.getTrustPlaneTimeoutMs());

        return new PcaIssuanceResult(
            response.pca,
            response.hop,
            response.p0,
            response.ops,
            response.catKid,
            response.exp
        );
    }

    /**
     * Register an executor key with the Trust Plane.
     *
     * <p>Calls: {@code POST {trustPlaneUrl}/v1/keys/executor}
     *
     * <p>Executors must register their public keys before they can submit PoCs.
     * The key is an Ed25519 public key (32 bytes) encoded in Base64.
     *
     * @param config      realm PIC configuration
     * @param kid         key identifier (unique name for this key)
     * @param publicKey   Base64-encoded Ed25519 public key (32 bytes)
     * @param serviceName human-readable service name for this executor
     * @throws TrustPlaneException on failure
     */
    public void registerExecutorKey(PicRealmConfig config, String kid,
                                    String publicKey, String serviceName)
            throws TrustPlaneException {
        RegisterExecutorRequest request = new RegisterExecutorRequest();
        request.kid = kid;
        request.publicKey = publicKey;
        request.serviceName = serviceName;

        String url = buildUrl(config.getTrustPlaneUrl(), "/v1/keys/executor");
        post(url, request, RegisterExecutorResponse.class,
             config.getTrustPlaneTimeoutMs());
    }

    /**
     * Revokes (deletes) an executor key from the Trust Plane.
     *
     * <p>Calls: {@code DELETE {trustPlaneUrl}/v1/keys/executor/{kid}}
     *
     * @param trustPlaneUrl the Trust Plane base URL
     * @param kid           key identifier to revoke
     * @param timeoutMs     timeout in milliseconds
     * @throws TrustPlaneException on failure
     */
    public void revokeExecutorKey(String trustPlaneUrl, String kid, int timeoutMs)
            throws TrustPlaneException {
        String encodedKid = URLEncoder.encode(kid, java.nio.charset.StandardCharsets.UTF_8);
        String url = buildUrl(trustPlaneUrl, "/v1/keys/executor/" + encodedKid);

        try {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .DELETE()
                .header("Accept", "application/json")
                .build();

            HttpResponse<String> httpResponse = httpClient.send(
                httpRequest, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() < 300) {
                return; // Success
            } else {
                TrustPlaneException.FailureType failureType =
                    classifyHttpError(httpResponse.statusCode(), httpResponse.body());
                String errorMessage =
                    extractErrorMessage(httpResponse.statusCode(), httpResponse.body());
                throw new TrustPlaneException(failureType, errorMessage,
                    httpResponse.statusCode(), httpResponse.body());
            }
        } catch (TrustPlaneException e) {
            throw e;
        } catch (HttpTimeoutException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.TIMEOUT,
                "Trust Plane call timed out: " + url, e);
        } catch (ConnectException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane unreachable: " + e.getMessage(), e);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane communication error: " + e.getMessage(), e);
        }
    }

    /**
     * Lists executor keys registered with the Trust Plane.
     *
     * <p>Calls: {@code GET {trustPlaneUrl}/v1/keys/executor}
     *
     * <p>Response matches Rust {@code ListExecutorsResponse}:
     * <pre>{@code
     * {
     *   "executors": ["executor-1", "executor-2"],
     *   "count": 2
     * }
     * }</pre>
     *
     * @param trustPlaneUrl the Trust Plane base URL
     * @param timeoutMs     timeout in milliseconds
     * @return a map containing "executors" (list of key IDs) and "count"
     * @throws TrustPlaneException on failure
     */
    public Map<String, Object> listExecutorKeys(String trustPlaneUrl, int timeoutMs)
            throws TrustPlaneException {
        String url = buildUrl(trustPlaneUrl, "/v1/keys/executor");

        try {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .GET()
                .header("Accept", "application/json")
                .build();

            HttpResponse<String> httpResponse = httpClient.send(
                httpRequest, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() < 300) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> result = objectMapper.readValue(
                        httpResponse.body(), Map.class);
                    return result;
                } catch (JsonProcessingException e) {
                    throw new TrustPlaneException(
                        TrustPlaneException.FailureType.INVALID_RESPONSE,
                        "Failed to parse executor keys response: " + e.getMessage(),
                        httpResponse.statusCode(), httpResponse.body(), e);
                }
            } else {
                TrustPlaneException.FailureType failureType =
                    classifyHttpError(httpResponse.statusCode(), httpResponse.body());
                String errorMessage =
                    extractErrorMessage(httpResponse.statusCode(), httpResponse.body());
                throw new TrustPlaneException(failureType, errorMessage,
                    httpResponse.statusCode(), httpResponse.body());
            }
        } catch (TrustPlaneException e) {
            throw e;
        } catch (HttpTimeoutException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.TIMEOUT,
                "Trust Plane call timed out: " + url, e);
        } catch (ConnectException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane unreachable: " + e.getMessage(), e);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane communication error: " + e.getMessage(), e);
        }
    }

    /**
     * Health check against the Trust Plane.
     *
     * <p>Calls: {@code GET {trustPlaneUrl}/health}
     *
     * @param trustPlaneUrl the Trust Plane base URL
     * @param timeoutMs     timeout in milliseconds
     * @return TrustPlaneStatus with health and latency info
     * @throws TrustPlaneException if the health check fails
     */
    public TrustPlaneStatus healthCheck(String trustPlaneUrl, int timeoutMs)
            throws TrustPlaneException {
        String url = buildUrl(trustPlaneUrl, "/health");
        long startTime = System.currentTimeMillis();

        try {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .GET()
                .header("Accept", "application/json")
                .build();

            HttpResponse<String> httpResponse = httpClient.send(
                httpRequest, HttpResponse.BodyHandlers.ofString());

            long latencyMs = System.currentTimeMillis() - startTime;

            if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() < 300) {
                HealthResponse healthResponse = objectMapper.readValue(
                    httpResponse.body(), HealthResponse.class);
                return new TrustPlaneStatus(true, healthResponse.status,
                                           healthResponse.version, latencyMs);
            } else {
                return new TrustPlaneStatus(false, "unhealthy", null, latencyMs);
            }
        } catch (HttpTimeoutException e) {
            long latencyMs = System.currentTimeMillis() - startTime;
            return new TrustPlaneStatus(false, "timeout", null, latencyMs);
        } catch (ConnectException e) {
            long latencyMs = System.currentTimeMillis() - startTime;
            return new TrustPlaneStatus(false, "unreachable", null, latencyMs);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            long latencyMs = System.currentTimeMillis() - startTime;
            return new TrustPlaneStatus(false, "error", null, latencyMs);
        }
    }

    @Override
    public void close() {
        // HttpClient does not require explicit close in Java 11+.
        // Included for future connection pool cleanup if needed.
    }

    // =========================================================================
    // Internal HTTP helpers
    // =========================================================================

    /**
     * Sends a POST request with JSON body and returns the parsed response.
     *
     * @param url          full URL
     * @param requestBody  object to serialize as JSON request body
     * @param responseType class to deserialize the JSON response into
     * @param timeoutMs    request timeout in milliseconds
     * @param <T>          response type
     * @return parsed response
     * @throws TrustPlaneException on any failure
     */
    <T> T post(String url, Object requestBody, Class<T> responseType,
               int timeoutMs) throws TrustPlaneException {
        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.INVALID_RESPONSE,
                "Failed to serialize request body: " + e.getMessage(), e);
        }

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMillis(timeoutMs))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .build();

        HttpResponse<String> httpResponse;
        try {
            httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.TIMEOUT,
                "Trust Plane call timed out after " + timeoutMs + "ms: " + url, e);
        } catch (ConnectException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane unreachable at " + url + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane communication error: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TrustPlaneException(
                TrustPlaneException.FailureType.UNREACHABLE,
                "Trust Plane call interrupted", e);
        }

        int status = httpResponse.statusCode();
        String body = httpResponse.body();

        if (status >= 200 && status < 300) {
            try {
                return objectMapper.readValue(body, responseType);
            } catch (JsonProcessingException e) {
                throw new TrustPlaneException(
                    TrustPlaneException.FailureType.INVALID_RESPONSE,
                    "Failed to parse Trust Plane response: " + e.getMessage(),
                    status, body, e);
            }
        }

        // Error response — try to parse as ErrorResponse for structured error info
        TrustPlaneException.FailureType failureType = classifyHttpError(status, body);
        String errorMessage = extractErrorMessage(status, body);

        throw new TrustPlaneException(failureType, errorMessage, status, body);
    }

    /**
     * Classifies an HTTP error status into a TrustPlaneException failure type.
     *
     * <p>Maps to the Rust {@code ApiError} variants and their HTTP status codes:
     * <ul>
     *   <li>403 with MONOTONICITY_VIOLATION code → MONOTONICITY_VIOLATION</li>
     *   <li>Other 4xx → REJECTED</li>
     *   <li>5xx → REJECTED</li>
     * </ul>
     */
    private TrustPlaneException.FailureType classifyHttpError(int status, String body) {
        if (status == 403 && body != null && body.contains("MONOTONICITY_VIOLATION")) {
            return TrustPlaneException.FailureType.MONOTONICITY_VIOLATION;
        }
        return TrustPlaneException.FailureType.REJECTED;
    }

    /**
     * Extracts a human-readable error message from the Trust Plane error response.
     *
     * <p>Attempts to parse the Rust {@code ErrorResponse} structure:
     * <pre>{@code { "error": "message", "code": "CODE", "details": {...} }}</pre>
     *
     * <p>Falls back to raw body if parsing fails.
     */
    private String extractErrorMessage(int status, String body) {
        if (body == null || body.isBlank()) {
            return "Trust Plane returned HTTP " + status;
        }
        try {
            ErrorResponse errorResponse = objectMapper.readValue(body, ErrorResponse.class);
            if (errorResponse.error != null) {
                return "Trust Plane error [" + errorResponse.code + "]: " + errorResponse.error;
            }
        } catch (JsonProcessingException ignored) {
            // Fall through to raw body
        }
        return "Trust Plane returned HTTP " + status + ": " + body;
    }

    /**
     * Builds a full URL from base URL and path.
     *
     * @param baseUrl the Trust Plane base URL (e.g., "https://trust-plane.example.com")
     * @param path    the API path (e.g., "/v1/pca/issue")
     * @return the full URL
     */
    static String buildUrl(String baseUrl, String path) {
        if (baseUrl == null) {
            throw new IllegalArgumentException("Trust Plane URL must not be null");
        }
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        return base + path;
    }

    // =========================================================================
    // Internal DTOs — match Rust API request/response structures exactly
    // =========================================================================

    /**
     * Matches Rust {@code IssuePcaRequest} in {@code provenance-plane/src/api/handlers/issue.rs}.
     */
    static class IssuePcaRequest {
        @JsonProperty("credential")
        String credential;

        @JsonProperty("credential_type")
        String credentialType;

        @JsonProperty("ops")
        List<String> ops;

        @JsonProperty("executor_binding")
        Map<String, String> executorBinding;
    }

    /**
     * Matches Rust {@code IssuePcaResponse} in {@code provenance-plane/src/api/handlers/issue.rs}.
     */
    static class IssuePcaResponse {
        @JsonProperty("pca")
        String pca;

        @JsonProperty("hop")
        int hop;

        @JsonProperty("p_0")
        String p0;

        @JsonProperty("ops")
        List<String> ops;

        @JsonProperty("cat_kid")
        String catKid;

        @JsonProperty("exp")
        String exp;
    }

    /**
     * Matches Trust Plane {@code ProcessPocRequest} in {@code provenance-plane/src/api/handlers/process.rs}.
     */
    static class ProcessPocRequest {
        @JsonProperty("predecessor_pca")
        String predecessorPca;

        @JsonProperty("requested_ops")
        List<String> requestedOps;

        @JsonProperty("executor_binding")
        Map<String, String> executorBinding;
    }

    /**
     * Matches Rust {@code ProcessPocResponse} in {@code provenance-plane/src/api/handlers/process.rs}.
     */
    static class ProcessPocResponse {
        @JsonProperty("pca")
        String pca;

        @JsonProperty("hop")
        int hop;

        @JsonProperty("p_0")
        String p0;

        @JsonProperty("ops")
        List<String> ops;

        @JsonProperty("cat_kid")
        String catKid;

        @JsonProperty("exp")
        String exp;
    }

    /**
     * Matches Rust {@code RegisterExecutorRequest} in {@code provenance-plane/src/api/handlers/keys.rs}.
     */
    static class RegisterExecutorRequest {
        @JsonProperty("kid")
        String kid;

        @JsonProperty("public_key")
        String publicKey;

        @JsonProperty("service_name")
        String serviceName;
    }

    /**
     * Matches Rust {@code RegisterExecutorResponse} in {@code provenance-plane/src/api/handlers/keys.rs}.
     */
    static class RegisterExecutorResponse {
        @JsonProperty("kid")
        String kid;

        @JsonProperty("message")
        String message;
    }

    /**
     * Matches Rust {@code HealthResponse} in {@code provenance-plane/src/api/mod.rs}.
     */
    static class HealthResponse {
        @JsonProperty("status")
        String status;

        @JsonProperty("version")
        String version;
    }

    /**
     * Matches Rust {@code ErrorResponse} in {@code provenance-plane/src/api/error.rs}.
     */
    static class ErrorResponse {
        @JsonProperty("error")
        String error;

        @JsonProperty("code")
        String code;

        @JsonProperty("details")
        Object details;
    }

}

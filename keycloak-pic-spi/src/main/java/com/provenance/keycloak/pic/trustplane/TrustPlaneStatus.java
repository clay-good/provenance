package com.provenance.keycloak.pic.trustplane;

/**
 * Status information from a Trust Plane health check.
 *
 * <p>Returned by {@link TrustPlaneClient#healthCheck(String, int)}.
 * Contains health status, server version, and round-trip latency.
 */
public class TrustPlaneStatus {
    private final boolean healthy;
    private final String status;
    private final String version;
    private final long latencyMs;

    public TrustPlaneStatus(boolean healthy, String status,
                            String version, long latencyMs) {
        this.healthy = healthy;
        this.status = status;
        this.version = version;
        this.latencyMs = latencyMs;
    }

    /** Whether the Trust Plane is healthy and reachable. */
    public boolean isHealthy() {
        return healthy;
    }

    /** Status string from the Trust Plane (e.g., "ok", "unhealthy", "timeout"). */
    public String getStatus() {
        return status;
    }

    /** Trust Plane server version, or null if not available. */
    public String getVersion() {
        return version;
    }

    /** Round-trip latency in milliseconds. */
    public long getLatencyMs() {
        return latencyMs;
    }

    @Override
    public String toString() {
        return "TrustPlaneStatus{healthy=" + healthy +
            ", status='" + status + '\'' +
            ", version='" + version + '\'' +
            ", latencyMs=" + latencyMs + '}';
    }
}

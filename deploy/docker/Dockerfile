# Trust Plane Server Dockerfile
#
# Multi-stage build for minimal runtime image
#
# Build: docker build -f deploy/docker/Dockerfile -t provenance-plane .
# Run:   docker run -p 8080:8080 provenance-plane

FROM rust:1.75 as builder

WORKDIR /app

# Copy the entire workspace
COPY . .

# Build only the provenance-plane binary in release mode
RUN cargo build --release -p provenance-plane

# Runtime stage - minimal Debian image
FROM debian:bookworm-slim

# Install CA certificates for HTTPS connections (e.g., federation)
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /app/target/release/provenance-plane /usr/local/bin/

# Default port for Trust Plane
EXPOSE 8080

# Environment variables with defaults
ENV TRUST_PLANE_PORT=8080
ENV TRUST_PLANE_LOG_LEVEL=info
ENV TRUST_PLANE_CAT_KID=trust-plane-cat

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root user for security
RUN useradd -r -s /bin/false trustplane
USER trustplane

CMD ["provenance-plane"]

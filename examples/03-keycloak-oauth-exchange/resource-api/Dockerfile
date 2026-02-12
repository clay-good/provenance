# Resource API Service
#
# Builds the resource-api TypeScript service for use in docker-compose.
# Requires the SDK to be available at build context.
#
# Build context must be the repository root so the SDK file reference resolves:
#   docker build -f examples/03-keycloak-oauth-exchange/resource-api/Dockerfile .

FROM node:20-slim

WORKDIR /app

# Copy and build the SDK first (the services depend on it via file: reference)
COPY sdks/typescript /app/sdks/typescript
RUN cd /app/sdks/typescript && npm install && npm run build

# Copy the service source
COPY examples/03-keycloak-oauth-exchange/resource-api/package.json /app/service/package.json
COPY examples/03-keycloak-oauth-exchange/resource-api/tsconfig.json /app/service/tsconfig.json
COPY examples/03-keycloak-oauth-exchange/resource-api/src /app/service/src

# Rewrite the SDK file reference to the absolute path inside the container
RUN cd /app/service && \
    sed -i 's|file:../../../sdks/typescript|file:/app/sdks/typescript|' package.json && \
    npm install && \
    npm run build

WORKDIR /app/service

EXPOSE 3001

ENV PORT=3001
ENV TRUST_PLANE_URL=http://trust-plane:8080

CMD ["node", "dist/index.js"]

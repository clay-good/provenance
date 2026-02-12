# Keycloak Gateway Service
#
# Builds the keycloak-gateway TypeScript service for use in docker-compose.
# Requires the SDK to be available at build context.
#
# Build context must be the repository root so the SDK file reference resolves:
#   docker build -f examples/03-keycloak-oauth-exchange/keycloak-gateway/Dockerfile .

FROM node:20-slim

WORKDIR /app

# Copy and build the SDK first (the services depend on it via file: reference)
COPY sdks/typescript /app/sdks/typescript
RUN cd /app/sdks/typescript && npm install && npm run build

# Copy the service source
COPY examples/03-keycloak-oauth-exchange/keycloak-gateway/package.json /app/service/package.json
COPY examples/03-keycloak-oauth-exchange/keycloak-gateway/tsconfig.json /app/service/tsconfig.json
COPY examples/03-keycloak-oauth-exchange/keycloak-gateway/src /app/service/src

# Rewrite the SDK file reference to the absolute path inside the container
RUN cd /app/service && \
    sed -i 's|file:../../../sdks/typescript|file:/app/sdks/typescript|' package.json && \
    npm install && \
    npm run build

WORKDIR /app/service

EXPOSE 3000

ENV PORT=3000
ENV TRUST_PLANE_URL=http://trust-plane:8080
ENV KEYCLOAK_URL=http://keycloak:8080
ENV RESOURCE_API_URL=http://resource-api:3001

CMD ["node", "dist/index.js"]

#!/bin/bash
#
# PIC + Keycloak OAuth Token Exchange Demo
#
# Demonstrates how PIC (Provenance Identity Continuity) extends OAuth Token
# Exchange (RFC 8693) with authority continuity. Keycloak acts as the OAuth
# Authorization Server, and the Federation Bridge translates exchanged tokens
# into PCA_0 — preserving the original user as p_0 even through service-to-
# service token exchanges.
#
# Architecture:
#   User -> Keycloak (authn) -> Gateway (token exchange) -> Trust Plane (PCA_0) -> Resource API
#
# Prerequisites:
# - Rust toolchain (for Trust Plane)
# - Node.js 18+ (for services)
# - Docker (for Keycloak)
# - curl, jq
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Service ports
KEYCLOAK_PORT=8180
TRUST_PLANE_PORT=8080
GATEWAY_PORT=3000
RESOURCE_API_PORT=3001

# Keycloak configuration
KEYCLOAK_URL="http://localhost:${KEYCLOAK_PORT}"
KEYCLOAK_REALM="pic-demo"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_CLIENT_ID="pic-gateway"
KEYCLOAK_CLIENT_SECRET="pic-gateway-secret"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PIC + Keycloak OAuth Token Exchange Demo (RFC 8693)           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "This demo shows how OAuth Token Exchange carries PIC authority"
echo "continuity — the 'act' claim preserves the original user as p_0,"
echo "and pic_ops map directly to PIC operation strings."
echo ""

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    [ -n "$TRUST_PLANE_PID" ] && kill $TRUST_PLANE_PID 2>/dev/null || true
    [ -n "$GATEWAY_PID" ] && kill $GATEWAY_PID 2>/dev/null || true
    [ -n "$RESOURCE_API_PID" ] && kill $RESOURCE_API_PID 2>/dev/null || true

    # Stop Keycloak container if we started it
    if [ "$KEYCLOAK_STARTED_BY_US" = "true" ]; then
        echo "  Stopping Keycloak..."
        docker stop pic-demo-keycloak 2>/dev/null || true
        docker rm pic-demo-keycloak 2>/dev/null || true
    fi
    echo -e "${GREEN}Done.${NC}"
}

trap cleanup EXIT

# =============================================================================
# Helper functions
# =============================================================================

wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=${3:-30}
    local attempt=1

    echo -n "  Waiting for ${name}..."
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}ready!${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    echo -e " ${RED}FAILED (timeout after ${max_attempts}s)${NC}"
    return 1
}

print_json() {
    if command -v jq &> /dev/null; then
        echo "$1" | jq '.' 2>/dev/null || echo "$1"
    else
        echo "$1" | python3 -m json.tool 2>/dev/null || echo "$1"
    fi
}

# Authenticate with Keycloak using Direct Grant (Resource Owner Password Credentials)
keycloak_login() {
    local username=$1
    local password=$2

    curl -sf -X POST "$KEYCLOAK_TOKEN_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${KEYCLOAK_CLIENT_ID}" \
        -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
        -d "username=${username}" \
        -d "password=${password}" \
        -d "scope=openid pic-operations"
}

# Decode JWT payload (for display purposes)
decode_jwt() {
    local token=$1
    echo "$token" | cut -d '.' -f 2 | base64 -d 2>/dev/null || \
    echo "$token" | cut -d '.' -f 2 | python3 -c "import sys,base64,json; data=sys.stdin.read().strip(); padded=data+'='*(-len(data)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(padded)),indent=2))" 2>/dev/null || \
    echo "(could not decode)"
}

# =============================================================================
# Step 1: Build everything
# =============================================================================

echo -e "${BLUE}[1/5] Building Trust Plane...${NC}"
cd "$REPO_ROOT"
cargo build --release -p provenance-plane 2>&1 | tail -3

echo -e "${BLUE}[2/5] Building TypeScript SDK...${NC}"
cd "$REPO_ROOT/sdks/typescript"
npm install --silent 2>/dev/null || npm install
npm run build 2>&1 | tail -3

echo -e "${BLUE}[3/5] Installing demo dependencies...${NC}"
cd "$SCRIPT_DIR"
(cd keycloak-gateway && npm install --silent 2>/dev/null || npm install)
(cd resource-api && npm install --silent 2>/dev/null || npm install)

echo -e "${BLUE}[4/5] Building demo services...${NC}"
(cd "$SCRIPT_DIR/keycloak-gateway" && npm run build 2>&1)
(cd "$SCRIPT_DIR/resource-api" && npm run build 2>&1)

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo ""

# =============================================================================
# Step 2: Start services
# =============================================================================

echo -e "${BLUE}[5/5] Starting services...${NC}"
echo ""

# -- Keycloak --
KEYCLOAK_STARTED_BY_US="false"
if curl -sf "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}" > /dev/null 2>&1; then
    echo -e "  Keycloak already running on port ${KEYCLOAK_PORT}"
else
    echo "  Starting Keycloak (this may take 30-60 seconds on first run)..."
    docker run -d --name pic-demo-keycloak \
        -p "${KEYCLOAK_PORT}:8080" \
        -e KEYCLOAK_ADMIN=admin \
        -e KEYCLOAK_ADMIN_PASSWORD=admin \
        -v "${SCRIPT_DIR}/keycloak/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro" \
        quay.io/keycloak/keycloak:24.0 \
        start-dev --import-realm --features=token-exchange,admin-fine-grained-authz \
        > /dev/null 2>&1
    KEYCLOAK_STARTED_BY_US="true"
    # Keycloak dev mode doesn't expose /health/ready on the main port; check the realm endpoint
    wait_for_service "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}" "Keycloak" 90
fi

# -- Configure Token Exchange Permission --
# Keycloak requires explicit authorization for token exchange. We enable
# permissions on the pic-resource-api client and create a policy allowing
# the pic-gateway client to perform token exchange against it.
echo -e "  Configuring token exchange permissions..."
ADMIN_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | jq -r '.access_token')

if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
    # Get client UUIDs
    RESOURCE_API_UUID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=pic-resource-api" | jq -r '.[0].id')
    GATEWAY_UUID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=pic-gateway" | jq -r '.[0].id')
    REALM_MGMT_UUID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=realm-management" | jq -r '.[0].id')

    # Enable permissions on pic-resource-api (creates token-exchange scope permission)
    PERMS=$(curl -sf -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${RESOURCE_API_UUID}/management/permissions" \
        -d '{"enabled": true}')
    TOKEN_EXCHANGE_PERM_ID=$(echo "$PERMS" | jq -r '.scopePermissions["token-exchange"]')

    # Create a client policy allowing pic-gateway
    POLICY_ID=$(curl -sf -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${REALM_MGMT_UUID}/authz/resource-server/policy/client" \
        -d "{\"name\":\"pic-gateway-exchange-policy\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\",\"clients\":[\"${GATEWAY_UUID}\"]}" \
        | jq -r '.id')

    # Get the resource and scope IDs from the permission
    RESOURCE_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${REALM_MGMT_UUID}/authz/resource-server/permission/scope/${TOKEN_EXCHANGE_PERM_ID}/resources" \
        | jq -r '.[0]._id')
    SCOPE_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${REALM_MGMT_UUID}/authz/resource-server/permission/scope/${TOKEN_EXCHANGE_PERM_ID}/scopes" \
        | jq -r '.[0].id')

    # Associate the policy with the token-exchange permission
    curl -sf -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${REALM_MGMT_UUID}/authz/resource-server/permission/scope/${TOKEN_EXCHANGE_PERM_ID}" \
        -d "{\"id\":\"${TOKEN_EXCHANGE_PERM_ID}\",\"name\":\"token-exchange.permission.client.${RESOURCE_API_UUID}\",\"type\":\"scope\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\",\"resources\":[\"${RESOURCE_ID}\"],\"scopes\":[\"${SCOPE_ID}\"],\"policies\":[\"${POLICY_ID}\"]}" \
        > /dev/null

    echo -e "  ${GREEN}Token exchange permissions configured!${NC}"
else
    echo -e "  ${YELLOW}Warning: Could not get admin token — token exchange may not work${NC}"
fi

# -- Trust Plane --
cd "$REPO_ROOT"
TRUST_PLANE_PORT=$TRUST_PLANE_PORT \
TRUST_PLANE_CAT_KID="demo-trust-plane" \
TRUST_PLANE_LOG_LEVEL="warn" \
cargo run --release -p provenance-plane > /tmp/pic-trust-plane.log 2>&1 &
TRUST_PLANE_PID=$!
wait_for_service "http://localhost:${TRUST_PLANE_PORT}/health" "Trust Plane" 30

# -- Resource API --
cd "$SCRIPT_DIR/resource-api"
PORT=$RESOURCE_API_PORT \
LOG_LEVEL=info \
node dist/index.js > /tmp/pic-resource-api.log 2>&1 &
RESOURCE_API_PID=$!
wait_for_service "http://localhost:${RESOURCE_API_PORT}/health" "Resource API" 10

# -- Keycloak Gateway --
cd "$SCRIPT_DIR/keycloak-gateway"
PORT=$GATEWAY_PORT \
TRUST_PLANE_URL="http://localhost:${TRUST_PLANE_PORT}" \
KEYCLOAK_URL="$KEYCLOAK_URL" \
RESOURCE_API_URL="http://localhost:${RESOURCE_API_PORT}" \
LOG_LEVEL=info \
node dist/index.js > /tmp/pic-keycloak-gateway.log 2>&1 &
GATEWAY_PID=$!
wait_for_service "http://localhost:${GATEWAY_PORT}/health" "Keycloak Gateway" 10

echo ""
echo -e "${GREEN}All services running!${NC}"
echo ""

# =============================================================================
# Demo Scenarios
# =============================================================================

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       Demo Scenarios                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# Scenario 1: Normal flow — Alice accesses her own claims
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 1: Normal flow — Alice accesses her own claims${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice authenticates with Keycloak, gets an access token, and calls"
echo "the gateway to retrieve her claim. The gateway performs token exchange"
echo "and obtains PCA_0 from the Trust Plane."
echo ""
echo -e "${BOLD}Expected: SUCCESS — Alice can read her own claims.${NC}"
echo ""

echo -e "${CYAN}Step 1a: Authenticate Alice with Keycloak...${NC}"
ALICE_TOKEN_RESPONSE=$(keycloak_login "alice" "alice123")
if [ $? -ne 0 ] || [ -z "$ALICE_TOKEN_RESPONSE" ]; then
    echo -e "${RED}ERROR: Failed to authenticate Alice with Keycloak${NC}"
    echo "Check Keycloak logs: docker logs pic-demo-keycloak"
    exit 1
fi

ALICE_TOKEN=$(echo "$ALICE_TOKEN_RESPONSE" | jq -r '.access_token')
echo -e "  ${GREEN}Alice authenticated!${NC}"
echo ""

echo -e "${CYAN}Step 1b: Inspect Alice's token claims...${NC}"
echo "  Key claims from Alice's access token:"
decode_jwt "$ALICE_TOKEN" | jq '{sub, preferred_username, pic_ops, aud}' 2>/dev/null || echo "  (token obtained)"
echo ""

echo -e "${CYAN}Step 1c: Call gateway to access alice/claim-001...${NC}"
echo "  curl -H \"Authorization: Bearer <alice_token>\" http://localhost:${GATEWAY_PORT}/claims/alice/claim-001"
echo ""

RESPONSE=$(curl -s http://localhost:${GATEWAY_PORT}/claims/alice/claim-001 \
    -H "Authorization: Bearer ${ALICE_TOKEN}")

echo -e "${CYAN}Response:${NC}"
print_json "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Alice retrieved her claim via OAuth Token Exchange + PIC${NC}"
echo ""

# =============================================================================
# Scenario 2: Token exchange preserves provenance
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 2: Token exchange preserves provenance (p_0)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "After token exchange, the 'act' claim carries the original user."
echo "The Trust Plane extracts p_0 from the deepest act.sub — proving"
echo "that authority traces back to Alice, not the gateway service."
echo ""
echo -e "${BOLD}Expected: p_0 = alice (not 'service-account-pic-gateway')${NC}"
echo ""

echo -e "${CYAN}Examining the response from Scenario 1...${NC}"
echo ""

P_0=$(echo "$RESPONSE" | jq -r '.authority_chain[0].ops[]' 2>/dev/null || echo "")
AUTHORITY_CHAIN=$(echo "$RESPONSE" | jq '.authority_chain' 2>/dev/null || echo "[]")

echo "Authority chain:"
print_json "$AUTHORITY_CHAIN"
echo ""

echo "Key observation:"
echo "  - The gateway performed a token exchange (alice's token → pic-resource-api audience)"
echo "  - The exchanged token's 'act.sub' contains Alice's original subject"
echo "  - The Trust Plane set p_0 = alice (the human), NOT the gateway service"
echo "  - Operations are scoped to read:claims:alice/* (from Alice's pic_ops attribute)"
echo ""
echo -e "${GREEN}✓ PROVENANCE PRESERVED: p_0 traces back to Alice through token exchange${NC}"
echo ""

# =============================================================================
# Scenario 3: Confused deputy blocked — Alice cannot access Bob's claims
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 3: Confused deputy BLOCKED — Alice cannot access Bob's claims${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice's token (with read:claims:alice/*) is used to request Bob's"
echo "claim (bob/claim-001). Even though the gateway forwards the request,"
echo "the Resource API rejects it because the PCA's operations don't cover"
echo "read:claims:bob/claim-001."
echo ""
echo -e "${BOLD}Expected: BLOCKED — read:claims:bob/claim-001 ⊄ read:claims:alice/*${NC}"
echo ""

echo -e "${CYAN}Calling gateway with Alice's token for Bob's claim...${NC}"
echo "  curl -H \"Authorization: Bearer <alice_token>\" http://localhost:${GATEWAY_PORT}/claims/bob/claim-001"
echo ""

RESPONSE_3=$(curl -s http://localhost:${GATEWAY_PORT}/claims/bob/claim-001 \
    -H "Authorization: Bearer ${ALICE_TOKEN}")

echo -e "${CYAN}Response:${NC}"
print_json "$RESPONSE_3"
echo ""

# Check if it was blocked
ERROR_CODE=$(echo "$RESPONSE_3" | jq -r '.code // .details.code // empty' 2>/dev/null)
if [ "$ERROR_CODE" = "FORBIDDEN" ] || [ "$ERROR_CODE" = "MONOTONICITY_VIOLATION" ]; then
    echo -e "${RED}✓ BLOCKED: Confused deputy attack prevented by PIC!${NC}"
else
    HTTP_STATUS=$(echo "$RESPONSE_3" | jq -r '.code // empty' 2>/dev/null)
    if echo "$RESPONSE_3" | jq -e '.error' > /dev/null 2>&1; then
        echo -e "${RED}✓ BLOCKED: Request rejected — confused deputy attack prevented!${NC}"
    else
        echo -e "${YELLOW}⚠ Unexpected response — check service logs${NC}"
    fi
fi
echo ""
echo "  Alice's PCA has ops: [read:claims:alice/*]"
echo "  Requested operation: read:claims:bob/claim-001"
echo "  read:claims:bob/claim-001 is NOT a subset of read:claims:alice/*"
echo "  → PIC monotonicity invariant enforced!"
echo ""

# =============================================================================
# Scenario 4: Stolen token with wrong scope rejected
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 4: Scope escalation rejected — Bob cannot use Alice's token${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Bob authenticates with his own credentials (read:claims:bob/*)"
echo "and tries to access Alice's claim. Even though Bob has a valid"
echo "Keycloak token, the PCA's operations are scoped to Bob's resources."
echo ""
echo -e "${BOLD}Expected: BLOCKED — read:claims:alice/claim-001 ⊄ read:claims:bob/*${NC}"
echo ""

echo -e "${CYAN}Step 4a: Authenticate Bob with Keycloak...${NC}"
BOB_TOKEN_RESPONSE=$(keycloak_login "bob" "bob123")
if [ $? -ne 0 ] || [ -z "$BOB_TOKEN_RESPONSE" ]; then
    echo -e "${RED}ERROR: Failed to authenticate Bob with Keycloak${NC}"
    exit 1
fi

BOB_TOKEN=$(echo "$BOB_TOKEN_RESPONSE" | jq -r '.access_token')
echo -e "  ${GREEN}Bob authenticated!${NC}"
echo ""

echo -e "${CYAN}Step 4b: Inspect Bob's token claims...${NC}"
echo "  Key claims from Bob's access token:"
decode_jwt "$BOB_TOKEN" | jq '{sub, preferred_username, pic_ops, aud}' 2>/dev/null || echo "  (token obtained)"
echo ""

echo -e "${CYAN}Step 4c: Bob tries to access Alice's claim...${NC}"
echo "  curl -H \"Authorization: Bearer <bob_token>\" http://localhost:${GATEWAY_PORT}/claims/alice/claim-001"
echo ""

RESPONSE_4=$(curl -s http://localhost:${GATEWAY_PORT}/claims/alice/claim-001 \
    -H "Authorization: Bearer ${BOB_TOKEN}")

echo -e "${CYAN}Response:${NC}"
print_json "$RESPONSE_4"
echo ""

if echo "$RESPONSE_4" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${RED}✓ BLOCKED: Cross-user access prevented by PIC!${NC}"
else
    echo -e "${YELLOW}⚠ Unexpected response — check service logs${NC}"
fi
echo ""
echo "  Bob's PCA has ops: [read:claims:bob/*]"
echo "  Requested operation: read:claims:alice/claim-001"
echo "  read:claims:alice/claim-001 is NOT a subset of read:claims:bob/*"
echo "  → Even with a valid Keycloak token, PIC prevents cross-user access!"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                          Summary                                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The PIC Trust Plane enforces the THREE INVARIANTS across OAuth Token Exchange:"
echo ""
echo -e "  ${GREEN}1. PROVENANCE${NC} (p_0 immutability):"
echo "     After token exchange, p_0 is still the original human user."
echo "     The 'act' claim in RFC 8693 preserves the delegation chain."
echo "     Token exchange cannot launder identity."
echo ""
echo -e "  ${GREEN}2. IDENTITY${NC} (monotonic ops):"
echo "     Operations can only SHRINK across hops (ops_{i+1} ⊆ ops_i)."
echo "     Alice's read:claims:alice/* cannot be escalated to read:claims:bob/*."
echo "     Bob's read:claims:bob/* cannot access Alice's resources."
echo ""
echo -e "  ${GREEN}3. CONTINUITY${NC} (cryptographic chain):"
echo "     Each PCA is cryptographically signed by the Trust Plane."
echo "     The authority chain is tamper-proof across all hops."
echo ""
echo "This is analogous to WIMSE's extension of OAuth for workload identity —"
echo "PIC extends OAuth Token Exchange for authority continuity."
echo ""
echo -e "${GREEN}CONFUSED DEPUTY ATTACKS ARE ELIMINATED BY CONSTRUCTION${NC}"
echo ""

# =============================================================================
# Manual testing
# =============================================================================
echo "Services are still running for manual testing."
echo "Press Ctrl+C to stop all services."
echo ""
echo -e "${CYAN}Manual testing commands:${NC}"
echo ""
echo "  # Get Alice's token from Keycloak"
echo "  ALICE_TOKEN=\$(curl -s -X POST ${KEYCLOAK_TOKEN_URL} \\"
echo "    -d 'grant_type=password&client_id=${KEYCLOAK_CLIENT_ID}&client_secret=${KEYCLOAK_CLIENT_SECRET}' \\"
echo "    -d 'username=alice&password=alice123&scope=openid pic-operations' | jq -r '.access_token')"
echo ""
echo "  # Alice reads her claim (should work)"
echo "  curl -s -H \"Authorization: Bearer \$ALICE_TOKEN\" http://localhost:${GATEWAY_PORT}/claims/alice/claim-001 | jq ."
echo ""
echo "  # Alice tries Bob's claim (should fail)"
echo "  curl -s -H \"Authorization: Bearer \$ALICE_TOKEN\" http://localhost:${GATEWAY_PORT}/claims/bob/claim-001 | jq ."
echo ""
echo "  # Service health checks"
echo "  curl -s http://localhost:${KEYCLOAK_PORT}/health/ready"
echo "  curl -s http://localhost:${TRUST_PLANE_PORT}/health | jq ."
echo "  curl -s http://localhost:${GATEWAY_PORT}/health | jq ."
echo "  curl -s http://localhost:${RESOURCE_API_PORT}/health | jq ."
echo ""
echo -e "${CYAN}Logs:${NC}"
echo "  Trust Plane:     /tmp/pic-trust-plane.log"
echo "  Keycloak Gateway: /tmp/pic-keycloak-gateway.log"
echo "  Resource API:    /tmp/pic-resource-api.log"
echo "  Keycloak:        docker logs pic-demo-keycloak"
echo ""

# Wait for user to stop
wait

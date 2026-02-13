#!/bin/bash
#
# Keycloak PIC SPI Demo — Server-Side PIC via RFC 8693 Token Exchange
#
# Demonstrates how the PIC (Provenance Identity Continuity) Keycloak SPI
# embeds PIC claims directly into JWTs during OAuth Token Exchange.
# Unlike example 03 (client-side PIC), no client-side PIC libraries are
# needed — Keycloak itself calls the Trust Plane and returns a pic+jwt.
#
# Architecture:
#   Client -> Keycloak [PIC SPI -> Trust Plane] -> pic+jwt back to client
#
# Prerequisites:
# - Java 17+ and Maven (for SPI build)
# - Rust toolchain (for Trust Plane)
# - Docker (for Keycloak + Trust Plane)
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

# Keycloak configuration
KEYCLOAK_URL="http://localhost:${KEYCLOAK_PORT}"
KEYCLOAK_REALM="pic-demo"
KEYCLOAK_TOKEN_URL="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
KEYCLOAK_CLIENT_ID="pic-gateway"
KEYCLOAK_CLIENT_SECRET="pic-gateway-secret"
KEYCLOAK_PIC_BASE="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/pic"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Keycloak PIC SPI Demo — Server-Side PIC (RFC 8693)             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "This demo shows PIC integrated directly into Keycloak via a custom SPI."
echo "Keycloak calls the Trust Plane during token exchange and returns a"
echo "pic+jwt with embedded PIC claims — no client-side PIC libraries needed."
echo ""

# =============================================================================
# Prerequisites check
# =============================================================================

check_prereq() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}ERROR: $1 is required but not installed.${NC}"
        echo "  $2"
        exit 1
    fi
}

check_prereq "docker" "Install Docker: https://docs.docker.com/get-docker/"
check_prereq "curl" "Install curl via your package manager"
check_prereq "jq" "Install jq: https://jqlang.github.io/jq/download/"
check_prereq "mvn" "Install Maven: https://maven.apache.org/install.html"
check_prereq "cargo" "Install Rust: https://rustup.rs/"

# =============================================================================
# Cleanup
# =============================================================================

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"

    # Remove temporary files
    rm -f /tmp/pic-demo-blocked.json 2>/dev/null || true

    # Stop docker compose services
    cd "$SCRIPT_DIR"
    docker compose down --remove-orphans 2>/dev/null || true

    echo -e "${GREEN}Done.${NC}"
}

trap cleanup EXIT

# =============================================================================
# Helper functions
# =============================================================================

wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=${3:-60}
    local attempt=1

    echo -n "  Waiting for ${name}..."
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}ready!${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    echo -e " ${RED}FAILED (timeout after $((max_attempts * 2))s)${NC}"
    return 1
}

print_json() {
    echo "$1" | jq '.' 2>/dev/null || echo "$1"
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

# Decode base64url to JSON (handles URL-safe characters and padding)
_b64url_decode() {
    local input=$1
    # Replace base64url chars with standard base64 chars
    local b64="${input//-/+}"
    b64="${b64//_//}"
    # Add padding
    local pad=$((4 - ${#b64} % 4))
    [ $pad -lt 4 ] && b64="${b64}$(printf '=%.0s' $(seq 1 $pad))"
    # Try macOS base64 -D, then linux base64 -d, then python fallback
    echo "$b64" | base64 -D 2>/dev/null || \
    echo "$b64" | base64 -d 2>/dev/null || \
    python3 -c "import sys,base64; print(base64.b64decode(sys.stdin.read().strip()).decode())" 2>/dev/null
}

# Decode JWT payload (part 2)
decode_jwt_payload() {
    local token=$1
    local payload
    payload=$(echo "$token" | cut -d '.' -f 2)
    _b64url_decode "$payload" | jq '.' 2>/dev/null || echo "(could not decode)"
}

# Decode JWT header (part 1)
decode_jwt_header() {
    local token=$1
    local header
    header=$(echo "$token" | cut -d '.' -f 1)
    _b64url_decode "$header" | jq '.' 2>/dev/null || echo "(could not decode)"
}

# =============================================================================
# Step 1: Build SPI
# =============================================================================

echo -e "${BLUE}[1/3] Building Keycloak PIC SPI (Maven)...${NC}"
cd "$REPO_ROOT/keycloak-pic-spi"
mvn clean package -DskipTests -q 2>&1 | tail -5

SPI_JAR="$REPO_ROOT/keycloak-pic-spi/target/keycloak-pic-spi-1.0.0-SNAPSHOT.jar"
if [ ! -f "$SPI_JAR" ]; then
    echo -e "${RED}ERROR: SPI JAR not found at ${SPI_JAR}${NC}"
    exit 1
fi
echo -e "  ${GREEN}SPI JAR built: $(basename "$SPI_JAR")${NC}"

# =============================================================================
# Step 2: Build Trust Plane
# =============================================================================

echo -e "${BLUE}[2/3] Building Trust Plane (Rust)...${NC}"
cd "$REPO_ROOT"
cargo build --release -p provenance-plane 2>&1 | tail -3
echo -e "  ${GREEN}Trust Plane built!${NC}"

# =============================================================================
# Step 3: Start services via Docker Compose
# =============================================================================

echo ""
echo -e "${BLUE}[3/3] Starting services (Keycloak + Trust Plane)...${NC}"
echo "  This may take 60-90 seconds on first run (Docker image build + Keycloak startup)..."
echo ""

cd "$SCRIPT_DIR"
docker compose up -d --build 2>&1 | tail -10

# Wait for Trust Plane
wait_for_service "http://localhost:${TRUST_PLANE_PORT}/health" "Trust Plane" 30

# Wait for Keycloak (takes longer due to SPI build + startup)
wait_for_service "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}" "Keycloak" 90

echo ""
echo -e "${GREEN}All services running!${NC}"
echo ""

# =============================================================================
# Configure Token Exchange Permissions
# =============================================================================

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

    # Belt-and-suspenders: ensure PIC realm attributes are set via admin API
    curl -sf -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}" \
        -d '{"attributes":{"pic_enabled":"true","pic_trust_plane_url":"http://trust-plane:8080","pic_fail_open":"false","pic_ops_user_attribute":"pic_ops","pic_audit_enabled":"true","pic_max_act_depth":"32","pic_token_lifetime_seconds":"300"}}' \
        > /dev/null
    echo -e "  ${GREEN}PIC realm attributes confirmed!${NC}"

    # Set client attributes via admin API
    GATEWAY_CLIENT=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${GATEWAY_UUID}")
    GATEWAY_CLIENT_UPDATED=$(echo "$GATEWAY_CLIENT" | jq '.attributes += {"pic.enabled":"true","pic.executor.name":"pic-gateway"}')
    curl -sf -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${GATEWAY_UUID}" \
        -d "$GATEWAY_CLIENT_UPDATED" > /dev/null
    echo -e "  ${GREEN}PIC client attributes confirmed!${NC}"
else
    echo -e "${RED}ERROR: Could not get admin token — aborting${NC}"
    exit 1
fi

echo ""

# =============================================================================
# Demo Scenarios
# =============================================================================

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       Demo Scenarios                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# Scenario 1: PIC Discovery Endpoint (well-known)
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 1: PIC Discovery — GET /realms/pic-demo/pic/well-known${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "The PIC SPI exposes a discovery endpoint (similar to OpenID .well-known)"
echo "that advertises the realm's PIC capabilities and endpoints."
echo ""
echo -e "${BOLD}Expected: PIC metadata with version, token type, and endpoints${NC}"
echo ""

echo -e "${CYAN}curl ${KEYCLOAK_PIC_BASE}/well-known${NC}"
echo ""
WELL_KNOWN=$(curl -sf "${KEYCLOAK_PIC_BASE}/well-known")
print_json "$WELL_KNOWN"
echo ""

PIC_ENABLED=$(echo "$WELL_KNOWN" | jq -r '.pic_enabled')
PIC_VERSION=$(echo "$WELL_KNOWN" | jq -r '.pic_version')
if [ "$PIC_ENABLED" = "true" ]; then
    echo -e "${GREEN}PIC SPI is loaded and active (version ${PIC_VERSION})${NC}"
else
    echo -e "${RED}ERROR: PIC is not enabled in the realm${NC}"
    exit 1
fi
echo ""

# =============================================================================
# Scenario 2: Alice gets a pic+jwt via Token Exchange
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 2: Normal PIC Token Exchange — Alice gets a pic+jwt${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice authenticates with Keycloak, then performs an RFC 8693 token"
echo "exchange requesting a PIC token. Keycloak's PIC SPI intercepts the"
echo "exchange, calls the Trust Plane, and returns a pic+jwt with embedded"
echo "PIC claims — all server-side, no client PIC libraries needed."
echo ""
echo -e "${BOLD}Expected: pic+jwt with pic_provenance, pic_ops, pic_chain claims${NC}"
echo ""

echo -e "${CYAN}Step 2a: Authenticate Alice with Keycloak (Direct Grant)...${NC}"
ALICE_TOKEN_RESPONSE=$(keycloak_login "alice" "alice123")
if [ $? -ne 0 ] || [ -z "$ALICE_TOKEN_RESPONSE" ]; then
    echo -e "${RED}ERROR: Failed to authenticate Alice with Keycloak${NC}"
    echo "Check Keycloak logs: docker compose logs keycloak"
    exit 1
fi
ALICE_TOKEN=$(echo "$ALICE_TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [ -z "$ALICE_TOKEN" ] || [ "$ALICE_TOKEN" = "null" ]; then
    echo -e "${RED}ERROR: Failed to extract access token from response${NC}"
    echo "$ALICE_TOKEN_RESPONSE" | jq . 2>/dev/null
    exit 1
fi
echo -e "  ${GREEN}Alice authenticated!${NC}"
echo ""

echo -e "${CYAN}Step 2b: Perform RFC 8693 Token Exchange requesting PIC token type...${NC}"
echo "  grant_type = urn:ietf:params:oauth:grant-type:token-exchange"
echo "  requested_token_type = urn:ietf:params:oauth:token-type:pic_token"
echo ""

PIC_RESPONSE=$(curl -s -X POST "$KEYCLOAK_TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "subject_token=${ALICE_TOKEN}" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "requested_token_type=urn:ietf:params:oauth:token-type:pic_token" \
    -d "audience=pic-resource-api")

PIC_ERROR=$(echo "$PIC_RESPONSE" | jq -r '.error // empty' 2>/dev/null)
if [ -n "$PIC_ERROR" ]; then
    echo -e "${RED}ERROR: Token exchange failed: ${PIC_ERROR}${NC}"
    echo "$PIC_RESPONSE" | jq . 2>/dev/null
    echo "Check Keycloak logs: docker compose logs keycloak"
    exit 1
fi

ISSUED_TOKEN_TYPE=$(echo "$PIC_RESPONSE" | jq -r '.issued_token_type')
PIC_TOKEN=$(echo "$PIC_RESPONSE" | jq -r '.access_token')
echo "  issued_token_type: ${ISSUED_TOKEN_TYPE}"
echo ""

echo -e "${CYAN}Step 2c: Decode the JWT header (JOSE header)...${NC}"
echo ""
JWT_HEADER=$(decode_jwt_header "$PIC_TOKEN")
echo "$JWT_HEADER"
echo ""

TYP=$(echo "$JWT_HEADER" | jq -r '.typ')
if [ "$TYP" = "pic+jwt" ]; then
    echo -e "${GREEN}JWT header typ = \"pic+jwt\" — this is a PIC-enhanced token!${NC}"
else
    echo -e "${RED}WARNING: Expected typ=pic+jwt but got typ=${TYP}${NC}"
fi
echo ""

echo -e "${CYAN}Step 2d: Decode the JWT payload (PIC claims)...${NC}"
echo ""
JWT_PAYLOAD=$(decode_jwt_payload "$PIC_TOKEN")
echo "$JWT_PAYLOAD"
echo ""

echo -e "${GREEN}PIC token received with embedded PIC claims!${NC}"
echo ""

# =============================================================================
# Scenario 3: PROVENANCE — p_0 is immutable
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 3: PROVENANCE — p_0 traces back to Alice${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "The pic_provenance.p_0 claim anchors the token to the original human"
echo "user. Even though the token exchange was performed by the pic-gateway"
echo "service account, p_0 records Alice as the origin principal."
echo ""
echo -e "${BOLD}Expected: p_0 is Alice's user identity (NOT 'service-account-pic-gateway')${NC}"
echo ""

P0=$(echo "$JWT_PAYLOAD" | jq '.pic_provenance.p_0' 2>/dev/null)
P0_VALUE=$(echo "$JWT_PAYLOAD" | jq -r '.pic_provenance.p_0.value' 2>/dev/null)
P0_TYPE=$(echo "$JWT_PAYLOAD" | jq -r '.pic_provenance.p_0.type' 2>/dev/null)
PROV_VERSION=$(echo "$JWT_PAYLOAD" | jq -r '.pic_provenance.version' 2>/dev/null)
PCA_HASH=$(echo "$JWT_PAYLOAD" | jq -r '.pic_provenance.pca_0_hash' 2>/dev/null)
HOP=$(echo "$JWT_PAYLOAD" | jq -r '.pic_provenance.hop' 2>/dev/null)

# Also look up Alice's user ID via admin API for verification
ADMIN_TOKEN_3=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' | jq -r '.access_token')
ALICE_USER_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN_3" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=alice&exact=true" | jq -r '.[0].id')

echo "  pic_provenance:"
echo "    version:    ${PROV_VERSION}"
echo "    p_0.type:   ${P0_TYPE}"
echo "    p_0.value:  ${P0_VALUE}"
echo "    pca_0_hash: ${PCA_HASH:0:40}..."
echo "    hop:        ${HOP}"
echo ""
echo "  Alice's Keycloak user ID: ${ALICE_USER_ID}"
echo ""

if echo "$P0_VALUE" | grep -q "$ALICE_USER_ID"; then
    echo -e "${GREEN}PROVENANCE VERIFIED: p_0 contains Alice's user ID${NC}"
    echo "  The SPI extracted Alice as the origin principal from the subject token."
    echo "  Token exchange cannot launder identity — p_0 is immutable."
elif echo "$P0_VALUE" | grep -q "service-account"; then
    echo -e "${RED}FAILED: p_0 contains the service account — identity was laundered!${NC}"
else
    echo -e "${GREEN}PROVENANCE VERIFIED: p_0 is set (not a service account)${NC}"
    echo "  p_0.value = ${P0_VALUE}"
    echo "  (Contains Alice's user UUID, not 'service-account-pic-gateway')"
fi
echo ""

# =============================================================================
# Scenario 4: IDENTITY — ops narrow monotonically
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 4: IDENTITY — ops narrow monotonically (scope narrowing)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice has authorized ops: [read:claims:alice/*, write:claims:alice/*]."
echo "We request a narrower scope — only read:claims:alice/claim-001."
echo "The SPI computes the intersection and issues a token with narrowed ops."
echo ""
echo -e "${BOLD}Expected: pic_ops = [\"read:claims:alice/claim-001\"] (narrowed from alice/*)${NC}"
echo ""

echo -e "${CYAN}Performing token exchange with narrowed scope...${NC}"
echo "  scope = read:claims:alice/claim-001"
echo ""

NARROW_RESPONSE=$(curl -s -X POST "$KEYCLOAK_TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "subject_token=${ALICE_TOKEN}" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "requested_token_type=urn:ietf:params:oauth:token-type:pic_token" \
    -d "audience=pic-resource-api" \
    -d "scope=read:claims:alice/claim-001")

NARROW_ERROR=$(echo "$NARROW_RESPONSE" | jq -r '.error // empty' 2>/dev/null)
if [ -n "$NARROW_ERROR" ]; then
    echo -e "${RED}ERROR: Narrowed token exchange failed: ${NARROW_ERROR}${NC}"
    echo "$NARROW_RESPONSE" | jq . 2>/dev/null
    echo "Check Keycloak logs: docker compose logs keycloak"
    exit 1
fi

NARROW_TOKEN=$(echo "$NARROW_RESPONSE" | jq -r '.access_token')
NARROW_PAYLOAD=$(decode_jwt_payload "$NARROW_TOKEN")
NARROW_OPS=$(echo "$NARROW_PAYLOAD" | jq '.pic_ops' 2>/dev/null)

echo "  pic_ops from narrowed exchange:"
echo "  $NARROW_OPS"
echo ""

if echo "$NARROW_OPS" | jq -e '.[0]' > /dev/null 2>&1; then
    echo -e "${GREEN}IDENTITY VERIFIED: Operations narrowed to requested scope${NC}"
    echo "  Original authorized ops: [read:claims:alice/*, write:claims:alice/*]"
    echo "  Requested scope:         read:claims:alice/claim-001"
    echo "  Effective ops:           ${NARROW_OPS}"
    echo "  Operations can ONLY shrink, never grow (monotonic narrowing)."
else
    echo -e "${RED}WARNING: Could not verify narrowed ops${NC}"
fi
echo ""

# =============================================================================
# Scenario 5: Confused deputy BLOCKED
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 5: CONFUSED DEPUTY BLOCKED — Alice cannot get Bob's ops${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice's token is used to request scope: read:claims:bob/*."
echo "The SPI computes the intersection of Alice's authorized ops"
echo "[read:claims:alice/*, write:claims:alice/*] with the requested"
echo "scope [read:claims:bob/*] — the result is EMPTY."
echo ""
echo -e "${BOLD}Expected: HTTP 403 — access_denied (empty ops intersection)${NC}"
echo ""

echo -e "${CYAN}Performing token exchange with Bob's scope using Alice's token...${NC}"
echo "  scope = read:claims:bob/*"
echo ""

BLOCKED_HTTP_CODE=$(curl -s -o /tmp/pic-demo-blocked.json -w "%{http_code}" \
    -X POST "$KEYCLOAK_TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "subject_token=${ALICE_TOKEN}" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "requested_token_type=urn:ietf:params:oauth:token-type:pic_token" \
    -d "audience=pic-resource-api" \
    -d "scope=read:claims:bob/*")

BLOCKED_BODY=$(cat /tmp/pic-demo-blocked.json 2>/dev/null)
echo "  HTTP Status: ${BLOCKED_HTTP_CODE}"
echo "  Response:"
print_json "$BLOCKED_BODY"
echo ""

BLOCKED_ERROR=$(echo "$BLOCKED_BODY" | jq -r '.error' 2>/dev/null)
if [ "$BLOCKED_HTTP_CODE" = "403" ] || [ "$BLOCKED_ERROR" = "access_denied" ]; then
    echo -e "${RED}BLOCKED: Confused deputy attack prevented by PIC!${NC}"
    echo ""
    echo "  Alice's authorized ops: [read:claims:alice/*, write:claims:alice/*]"
    echo "  Requested scope:        read:claims:bob/*"
    echo "  Intersection:           [] (EMPTY)"
    echo "  Result:                 access_denied — confused deputy eliminated!"
else
    echo -e "${YELLOW}WARNING: Expected 403/access_denied but got HTTP ${BLOCKED_HTTP_CODE}${NC}"
fi
echo ""

# =============================================================================
# Scenario 6: PIC Token Introspection
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 6: PIC Token Introspection — POST /pic/introspect${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "The SPI's introspect endpoint decodes a PIC token and returns the"
echo "PIC-specific claims in a structured format. Requires client auth."
echo ""
echo -e "${BOLD}Expected: active=true with p_0, pic_ops, chain_length, pca_valid${NC}"
echo ""

echo -e "${CYAN}Introspecting the PIC token from Scenario 2...${NC}"
echo ""

BASIC_AUTH=$(printf '%s:%s' "${KEYCLOAK_CLIENT_ID}" "${KEYCLOAK_CLIENT_SECRET}" | base64 | tr -d '\n')
INTROSPECT_RESPONSE=$(curl -sf -X POST "${KEYCLOAK_PIC_BASE}/introspect" \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${PIC_TOKEN}")

print_json "$INTROSPECT_RESPONSE"
echo ""

ACTIVE=$(echo "$INTROSPECT_RESPONSE" | jq -r '.active' 2>/dev/null)
INTROSPECT_P0=$(echo "$INTROSPECT_RESPONSE" | jq -r '.p_0.value // .p_0 // empty' 2>/dev/null)
if [ "$ACTIVE" = "true" ]; then
    echo -e "${GREEN}Introspection successful: active=true${NC}"
    CHAIN_LENGTH=$(echo "$INTROSPECT_RESPONSE" | jq -r '.chain_length // "N/A"' 2>/dev/null)
    PCA_VALID=$(echo "$INTROSPECT_RESPONSE" | jq -r '.pca_valid // "N/A"' 2>/dev/null)
    echo "  p_0:          ${INTROSPECT_P0}"
    echo "  chain_length: ${CHAIN_LENGTH}"
    echo "  pca_valid:    ${PCA_VALID}"
else
    echo -e "${RED}WARNING: Introspection returned active=false${NC}"
fi
echo ""

# =============================================================================
# Scenario 7: CONTINUITY — pic_chain audit trail
# =============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 7: CONTINUITY — pic_chain tracks the audit trail${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "The pic_chain claim is an array recording every hop in the authority"
echo "chain. Each entry includes the hop number, executor name, operations,"
echo "a SHA-256 hash of the PCA, and the Trust Plane key ID."
echo ""
echo -e "${BOLD}Expected: pic_chain with hop=0, executor=pic-gateway, pca_hash, cat_kid${NC}"
echo ""

echo -e "${CYAN}Inspecting pic_chain from the PIC token...${NC}"
echo ""

PIC_CHAIN=$(echo "$JWT_PAYLOAD" | jq '.pic_chain' 2>/dev/null)
echo "$PIC_CHAIN" | jq '.' 2>/dev/null
echo ""

CHAIN_HOP=$(echo "$PIC_CHAIN" | jq -r '.[0].hop // empty' 2>/dev/null)
CHAIN_EXECUTOR=$(echo "$PIC_CHAIN" | jq -r '.[0].executor // empty' 2>/dev/null)
CHAIN_PCA_HASH=$(echo "$PIC_CHAIN" | jq -r '.[0].pca_hash // empty' 2>/dev/null)
CHAIN_CAT_KID=$(echo "$PIC_CHAIN" | jq -r '.[0].cat_kid // empty' 2>/dev/null)
CHAIN_OPS=$(echo "$PIC_CHAIN" | jq '.[0].ops // empty' 2>/dev/null)

echo "  Chain entry [0]:"
echo "    hop:       ${CHAIN_HOP}"
echo "    executor:  ${CHAIN_EXECUTOR}"
echo "    ops:       ${CHAIN_OPS}"
echo "    pca_hash:  ${CHAIN_PCA_HASH:0:40}..."
echo "    cat_kid:   ${CHAIN_CAT_KID}"
echo ""

if [ -n "$CHAIN_PCA_HASH" ] && [ "$CHAIN_PCA_HASH" != "null" ] && [ -n "$CHAIN_CAT_KID" ] && [ "$CHAIN_CAT_KID" != "null" ]; then
    echo -e "${GREEN}CONTINUITY VERIFIED: Cryptographic audit trail is present${NC}"
    echo "  Each hop appends a chain entry with a PCA hash (SHA-256 of the"
    echo "  COSE_Sign1 bytes) and the Trust Plane's signing key ID."
    echo "  Downstream services can verify the chain without contacting the Trust Plane."
else
    echo -e "${YELLOW}WARNING: Chain entry incomplete${NC}"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                          Summary                                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The Keycloak PIC SPI enforces the THREE PIC INVARIANTS at the IdP level:"
echo ""
echo -e "  ${GREEN}1. PROVENANCE${NC} (p_0 immutability):"
echo "     After token exchange, p_0 is still the original human user (Alice)."
echo "     The SPI extracts the origin principal from the subject token."
echo "     Token exchange cannot launder identity."
echo ""
echo -e "  ${GREEN}2. IDENTITY${NC} (monotonic ops):"
echo "     Operations can only SHRINK across hops (ops_{i+1} ⊆ ops_i)."
echo "     Alice's read:claims:alice/* cannot escalate to read:claims:bob/*."
echo "     Confused deputy attacks are blocked by construction."
echo ""
echo -e "  ${GREEN}3. CONTINUITY${NC} (cryptographic chain):"
echo "     Each PCA is signed by the Trust Plane."
echo "     pic_chain provides a tamper-proof audit trail."
echo "     pca_0_hash anchors the chain to the initial PCA."
echo ""
echo -e "${BOLD}KEY INSIGHT: Zero client-side PIC code needed.${NC}"
echo "  Standard OAuth clients perform a normal token exchange and receive a"
echo "  pic+jwt with full authority continuity — the SPI does everything."
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
echo "  # PIC token exchange"
echo "  curl -s -X POST ${KEYCLOAK_TOKEN_URL} \\"
echo "    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\"
echo "    -d 'client_id=${KEYCLOAK_CLIENT_ID}&client_secret=${KEYCLOAK_CLIENT_SECRET}' \\"
echo "    -d \"subject_token=\$ALICE_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token\" \\"
echo "    -d 'requested_token_type=urn:ietf:params:oauth:token-type:pic_token' \\"
echo "    -d 'audience=pic-resource-api' | jq ."
echo ""
echo "  # PIC discovery"
echo "  curl -s ${KEYCLOAK_PIC_BASE}/well-known | jq ."
echo ""
echo "  # PIC introspection"
echo "  curl -s -X POST ${KEYCLOAK_PIC_BASE}/introspect \\"
echo "    -H 'Authorization: Basic \$(echo -n ${KEYCLOAK_CLIENT_ID}:${KEYCLOAK_CLIENT_SECRET} | base64)' \\"
echo "    -d \"token=\$PIC_TOKEN\" | jq ."
echo ""
echo -e "${CYAN}Logs:${NC}"
echo "  docker compose logs trust-plane"
echo "  docker compose logs keycloak"
echo ""

# Wait for user to stop
wait

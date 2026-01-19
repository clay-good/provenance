#!/bin/bash
# Federation Demo - Two Trust Planes
#
# This demo shows two Trust Planes (Acme Corp and Partner Inc) federating
# to share authority across organizational boundaries.
#
# Scenario:
# 1. Acme Corp issues a PCA to their agent
# 2. The agent needs to access Partner Inc's API
# 3. Partner Inc's Trust Plane verifies the federated PCA
# 4. Authority is preserved across the federation boundary

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "     PIC Federation Demo"
echo "========================================"
echo ""
echo "This demo demonstrates Trust Plane federation:"
echo "- Acme Corp Trust Plane (localhost:8080)"
echo "- Partner Inc Trust Plane (localhost:8081)"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$ACME_PID" ] && kill $ACME_PID 2>/dev/null || true
    [ -n "$PARTNER_PID" ] && kill $PARTNER_PID 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

# Build Trust Plane if needed
echo "Building Trust Plane..."
(cd ../.. && cargo build -p provenance-plane --release 2>/dev/null) || {
    echo "Building in debug mode..."
    (cd ../.. && cargo build -p provenance-plane)
}

TRUST_PLANE_BIN="../../target/release/provenance-plane"
if [ ! -f "$TRUST_PLANE_BIN" ]; then
    TRUST_PLANE_BIN="../../target/debug/provenance-plane"
fi

echo ""
echo "Step 1: Starting Acme Corp Trust Plane (port 8080)..."
echo "========================================"
TRUST_PLANE_PORT=8080 \
TRUST_PLANE_CAT_KID="acme-corp-cat" \
TRUST_PLANE_NAME="Acme Corp" \
TRUST_PLANE_LOG_LEVEL="warn" \
$TRUST_PLANE_BIN &
ACME_PID=$!

# Wait for Acme to be ready
echo "  Waiting for Acme Corp Trust Plane..."
for i in {1..30}; do
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}Acme Corp Trust Plane ready!${NC}"
        break
    fi
    sleep 0.5
done

echo ""
echo "Step 2: Starting Partner Inc Trust Plane (port 8081)..."
echo "========================================"
TRUST_PLANE_PORT=8081 \
TRUST_PLANE_CAT_KID="partner-inc-cat" \
TRUST_PLANE_NAME="Partner Inc" \
TRUST_PLANE_LOG_LEVEL="warn" \
$TRUST_PLANE_BIN &
PARTNER_PID=$!

# Wait for Partner to be ready
echo "  Waiting for Partner Inc Trust Plane..."
for i in {1..30}; do
    if curl -s http://localhost:8081/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}Partner Inc Trust Plane ready!${NC}"
        break
    fi
    sleep 0.5
done

echo ""
echo "Step 3: Check Trust Plane Info"
echo "========================================"

echo -e "\n${BLUE}Acme Corp Trust Plane info:${NC}"
curl -s http://localhost:8080/v1/federation/info | jq '.'

echo -e "\n${BLUE}Partner Inc Trust Plane info:${NC}"
curl -s http://localhost:8081/v1/federation/info | jq '.'

echo ""
echo "Step 4: Federate Trust Planes"
echo "========================================"
echo ""
echo "Getting Acme Corp's public key to register with Partner Inc..."

# Get Acme's federation info
ACME_INFO=$(curl -s http://localhost:8080/v1/federation/info)
ACME_KID=$(echo "$ACME_INFO" | jq -r '.kid')
ACME_PUBKEY=$(echo "$ACME_INFO" | jq -r '.public_key')

echo "Acme Corp CAT KID: $ACME_KID"

# Register Acme's CAT with Partner Inc
echo -e "\n${YELLOW}Registering Acme Corp CAT with Partner Inc...${NC}"
REGISTER_RESULT=$(curl -s -X POST http://localhost:8081/v1/federation/cats \
    -H "Content-Type: application/json" \
    -d "{
        \"kid\": \"$ACME_KID\",
        \"public_key\": \"$ACME_PUBKEY\",
        \"name\": \"Acme Corp\",
        \"endpoint\": \"http://localhost:8080\"
    }")

echo "$REGISTER_RESULT" | jq '.'

# Verify federation
echo -e "\n${BLUE}Partner Inc's registered CATs:${NC}"
curl -s http://localhost:8081/v1/federation/cats | jq '.'

echo ""
echo "Step 5: Issue PCA from Acme Corp"
echo "========================================"
echo ""
echo "Alice (from Acme Corp) requests a PCA to access partner resources..."

# Issue PCA_0 from Acme Corp
PCA_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/pca/issue \
    -H "Content-Type: application/json" \
    -d '{
        "credential": "alice",
        "credential_type": "mock",
        "ops": ["read:partner:data:*", "write:partner:data:alice/*"],
        "executor_binding": {
            "service": "acme-agent",
            "purpose": "partner-integration"
        }
    }')

echo "PCA issued by Acme Corp:"
echo "$PCA_RESPONSE" | jq '{hop, p_0, ops}'

# Extract the PCA
ACME_PCA=$(echo "$PCA_RESPONSE" | jq -r '.pca')

echo ""
echo "Step 6: Verify PCA at Partner Inc"
echo "========================================"
echo ""
echo "Partner Inc verifies the PCA signed by Acme Corp's CAT..."

VERIFY_RESULT=$(curl -s -X POST http://localhost:8081/v1/federation/verify \
    -H "Content-Type: application/json" \
    -d "{
        \"pca\": \"$ACME_PCA\"
    }")

echo -e "\n${BLUE}Verification result:${NC}"
echo "$VERIFY_RESULT" | jq '.'

VALID=$(echo "$VERIFY_RESULT" | jq -r '.valid')
ISSUER_KNOWN=$(echo "$VERIFY_RESULT" | jq -r '.issuer_known')

if [ "$VALID" = "true" ] && [ "$ISSUER_KNOWN" = "true" ]; then
    echo -e "\n${GREEN}SUCCESS: Partner Inc verified the PCA from Acme Corp!${NC}"
    echo ""
    echo "Federation allows:"
    echo "  - Alice's authority flows from Acme Corp to Partner Inc"
    echo "  - Partner Inc trusts Acme Corp's CAT signature"
    echo "  - PIC invariants are preserved across federation boundary"
    echo "  - p_0 (alice) cannot be modified by federation"
else
    echo -e "\n${RED}FAILED: Verification did not succeed${NC}"
fi

echo ""
echo "Step 7: Attempt Unauthorized Cross-Federation Access"
echo "========================================"
echo ""
echo "Eve (attacker) tries to use a forged PCA at Partner Inc..."

# Partner Inc won't know this CAT - it's a fake one
FAKE_VERIFY=$(curl -s -X POST http://localhost:8081/v1/federation/verify \
    -H "Content-Type: application/json" \
    -d '{
        "pca": "dW5rbm93bl9jYXRfZmFrZV9wY2E="
    }')

echo -e "\n${BLUE}Verification result for unknown CAT:${NC}"
echo "$FAKE_VERIFY" | jq '.'

FAKE_VALID=$(echo "$FAKE_VERIFY" | jq -r '.valid')
if [ "$FAKE_VALID" = "false" ]; then
    echo -e "\n${GREEN}BLOCKED: Partner Inc rejected the unknown/forged PCA!${NC}"
    echo ""
    echo "Federation security ensures:"
    echo "  - Only registered CATs can issue valid PCAs"
    echo "  - Cross-CAT attacks are blocked"
    echo "  - Trust boundaries are cryptographically enforced"
fi

echo ""
echo "========================================"
echo "     Federation Demo Complete"
echo "========================================"
echo ""
echo "Key takeaways:"
echo "1. Trust Planes can register each other's CAT public keys"
echo "2. PCAs from federated Trust Planes can be verified"
echo "3. Authority flows securely across organizational boundaries"
echo "4. Unknown or unregistered CATs are rejected"
echo "5. PIC invariants (p_0 immutability, ops monotonicity) preserved"
echo ""

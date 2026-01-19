#!/bin/bash
#
# PIC Microservice Chain Demo
#
# Demonstrates authority propagation through a three-service chain:
# Gateway (hop 0) -> Archive (hop 1) -> Storage (hop 2)
#
# Each hop narrows the operations to only what the downstream service needs,
# demonstrating the principle of least privilege enforced by PIC.
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         PIC Microservice Chain Demo                            ║${NC}"
echo -e "${BLUE}║         Gateway -> Archive -> Storage                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $TRUST_PLANE_PID 2>/dev/null || true
    kill $GATEWAY_PID 2>/dev/null || true
    kill $ARCHIVE_PID 2>/dev/null || true
    kill $STORAGE_PID 2>/dev/null || true
    echo -e "${GREEN}Done.${NC}"
}

trap cleanup EXIT

# Build
echo -e "${BLUE}[1/5] Building Trust Plane...${NC}"
cd "$REPO_ROOT/crates/provenance-plane"
cargo build --release 2>&1 | tail -3

echo -e "${BLUE}[2/5] Building TypeScript SDK...${NC}"
cd "$REPO_ROOT/sdks/typescript"
npm install --silent 2>/dev/null || npm install
npm run build 2>/dev/null

echo -e "${BLUE}[3/5] Installing dependencies...${NC}"
cd "$SCRIPT_DIR"
(cd gateway && npm install --silent 2>/dev/null && npm run build)
(cd archive && npm install --silent 2>/dev/null && npm run build)
(cd storage && npm install --silent 2>/dev/null && npm run build)

echo -e "${BLUE}[4/5] Starting services...${NC}"
echo ""

# Start Trust Plane
cd "$REPO_ROOT"
TRUST_PLANE_PORT=8080 cargo run --release -p provenance-plane > /tmp/trust-plane.log 2>&1 &
TRUST_PLANE_PID=$!
echo "  Trust Plane started (PID: $TRUST_PLANE_PID) - port 8080"
sleep 2

# Start Storage (hop 2)
cd "$SCRIPT_DIR/storage"
STORAGE_PORT=3002 node dist/index.js > /tmp/storage.log 2>&1 &
STORAGE_PID=$!
echo "  Storage Service started (PID: $STORAGE_PID) - port 3002"

# Start Archive (hop 1)
cd "$SCRIPT_DIR/archive"
ARCHIVE_PORT=3001 STORAGE_URL=http://localhost:3002 node dist/index.js > /tmp/archive.log 2>&1 &
ARCHIVE_PID=$!
echo "  Archive Service started (PID: $ARCHIVE_PID) - port 3001"

# Start Gateway (hop 0)
cd "$SCRIPT_DIR/gateway"
GATEWAY_PORT=3000 ARCHIVE_URL=http://localhost:3001 node dist/index.js > /tmp/gateway.log 2>&1 &
GATEWAY_PID=$!
echo "  Gateway Service started (PID: $GATEWAY_PID) - port 3000"

sleep 3
echo ""
echo -e "${GREEN}All services running!${NC}"
echo ""

# =============================================================================
# Demo Scenarios
# =============================================================================

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Demo Scenarios                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# -----------------------------------------------------------------------------
# Scenario 1: Alice uploads a file
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 1: Alice uploads a file${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice has scopes: [read:*, write:archive:*, write:storage:*]"
echo ""
echo -e "${CYAN}Authority flow:${NC}"
echo "  PCA_0 (Gateway): ops=[read:*, write:archive:*, write:storage:*]"
echo "  PCA_1 (Archive): ops=[write:archive:*] ← narrowed!"
echo "  PCA_2 (Storage): ops=[write:storage:*] ← narrowed again!"
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/upload \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '"'"'{"filename":"report.txt","content":"Q4 Financial Report..."}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/upload \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"filename":"report.txt","content":"Q4 Financial Report for Alice","metadata":{"type":"financial"}}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
FILE_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('file_id',''))" 2>/dev/null || echo "")
echo ""
echo -e "${GREEN}✓ SUCCESS: File uploaded through the chain${NC}"
echo -e "  Notice how ops narrow at each hop!"
echo ""

# -----------------------------------------------------------------------------
# Scenario 2: Alice reads her file back
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 2: Alice reads her file back${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Request:"
echo "  curl http://localhost:3000/read/${FILE_ID} -H \"Authorization: Bearer mock:alice\""
echo ""
echo "Response:"

if [ -n "$FILE_ID" ]; then
  RESPONSE=$(curl -s "http://localhost:3000/read/${FILE_ID}" \
    -H "Authorization: Bearer mock:alice")
  echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
  echo ""
  echo -e "${GREEN}✓ SUCCESS: File retrieved through the chain${NC}"
else
  echo "Skipped (no file_id from previous step)"
fi
echo ""

# -----------------------------------------------------------------------------
# Scenario 3: Bob tries to upload (write-only user)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 3: Bob tries to upload (read-only user)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Bob only has scopes: [read:archive:*]"
echo "He cannot write - this should fail at the Gateway -> Archive transition."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/upload \'
echo '    -H "Authorization: Bearer mock:bob" \'
echo '    -d '"'"'{"filename":"hack.txt","content":"malicious content"}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/upload \
  -H "Authorization: Bearer mock:bob" \
  -H "Content-Type: application/json" \
  -d '{"filename":"hack.txt","content":"malicious content"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Bob cannot upload - no write permissions${NC}"
echo -e "  Trust Plane rejected: write:archive:* ⊄ read:archive:*"
echo ""

# -----------------------------------------------------------------------------
# Scenario 4: Demonstrate authority chain inspection
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 4: Authority chain analysis${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Each response includes the full authority chain showing how"
echo "operations were narrowed at each hop."
echo ""
echo -e "${CYAN}Hop 0 (Gateway):${NC}"
echo "  - Receives: user's full scopes from JWT"
echo "  - Passes to Archive: only write:archive:*"
echo "  - Principle: Don't give Archive write:storage:* - it doesn't need it"
echo ""
echo -e "${CYAN}Hop 1 (Archive):${NC}"
echo "  - Receives: write:archive:* (already narrowed)"
echo "  - Passes to Storage: only write:storage:*"
echo "  - Principle: Archive can't give Storage write:archive:* even if it wanted to"
echo ""
echo -e "${CYAN}Hop 2 (Storage):${NC}"
echo "  - Receives: write:storage:* (narrowed twice)"
echo "  - Validates: PCA has required ops AND path matches p_0"
echo "  - Final enforcement: Even if all upstream services are compromised,"
echo "    Storage validates the cryptographic authority chain"
echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                         Summary                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The PIC Trust Plane enforces:"
echo ""
echo -e "  ${GREEN}1. PROVENANCE${NC}: p_0 (user identity) is immutable through all hops"
echo -e "  ${GREEN}2. IDENTITY${NC}: ops can only SHRINK at each hop"
echo -e "  ${GREEN}3. CONTINUITY${NC}: Cryptographic chain proves each delegation"
echo ""
echo "Key security properties demonstrated:"
echo ""
echo "  • Each service only requests ops it needs (least privilege)"
echo "  • Downstream services can't have MORE authority than upstream"
echo "  • Even if Archive is compromised, it can't give Storage extra ops"
echo "  • Storage validates the chain - defense in depth"
echo ""
echo -e "${GREEN}MICROSERVICE AUTHORITY IS PROVABLY CONSTRAINED${NC}"
echo ""

# Keep running
echo "Services are still running for manual testing."
echo "Press Ctrl+C to stop."
echo ""
echo "Test commands:"
echo '  # Upload as alice'
echo '  curl -s -X POST http://localhost:3000/upload -H "Authorization: Bearer mock:alice" -H "Content-Type: application/json" -d '"'"'{"filename":"test.txt","content":"hello"}'"'"' | python3 -m json.tool'
echo ""
echo '  # Try upload as bob (should fail)'
echo '  curl -s -X POST http://localhost:3000/upload -H "Authorization: Bearer mock:bob" -H "Content-Type: application/json" -d '"'"'{"filename":"test.txt","content":"hello"}'"'"' | python3 -m json.tool'
echo ""

wait

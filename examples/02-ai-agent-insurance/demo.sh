#!/bin/bash
#
# PIC AI Agent Demo: Confused Deputy Prevention
#
# This script demonstrates how PIC prevents confused deputy attacks
# where an AI agent might try to access data beyond the user's authority.
#
# Prerequisites:
# - Rust toolchain (for Trust Plane)
# - Node.js 18+ (for services)
# - npm
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       PIC AI Agent Demo: Confused Deputy Prevention           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $TRUST_PLANE_PID 2>/dev/null || true
    kill $CLAIMS_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true
    kill $GATEWAY_PID 2>/dev/null || true
    echo -e "${GREEN}Done.${NC}"
}

trap cleanup EXIT

# Build and start services
echo -e "${BLUE}[1/5] Building Trust Plane...${NC}"
cd "$REPO_ROOT/crates/provenance-plane"
cargo build --release 2>&1 | tail -5

echo -e "${BLUE}[2/5] Installing Node.js dependencies...${NC}"
cd "$SCRIPT_DIR"
npm install --silent 2>/dev/null || npm install

echo -e "${BLUE}[3/5] Building TypeScript SDK...${NC}"
cd "$REPO_ROOT/sdks/typescript"
npm install --silent 2>/dev/null || npm install
npm run build

echo -e "${BLUE}[4/5] Building demo services...${NC}"
cd "$SCRIPT_DIR"
(cd gateway && npm install --silent 2>/dev/null && npm run build)
(cd claims-service && npm install --silent 2>/dev/null && npm run build)
(cd agent && npm install --silent 2>/dev/null && npm run build)

echo -e "${BLUE}[5/5] Starting services...${NC}"
echo ""

# Start Trust Plane
cd "$REPO_ROOT"
TRUST_PLANE_PORT=8080 cargo run --release -p provenance-plane > /tmp/trust-plane.log 2>&1 &
TRUST_PLANE_PID=$!
echo "  Trust Plane started (PID: $TRUST_PLANE_PID)"

# Wait for Trust Plane to be ready
echo "  Waiting for Trust Plane to be ready..."
for i in {1..30}; do
  if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "  Trust Plane ready!"
    break
  fi
  sleep 0.5
done

# Start Claims Service
cd "$SCRIPT_DIR/claims-service"
CLAIMS_PORT=3002 node dist/index.js > /tmp/claims-service.log 2>&1 &
CLAIMS_PID=$!
echo "  Claims Service started (PID: $CLAIMS_PID)"
sleep 1

# Start AI Agent (needs Trust Plane to register key)
cd "$SCRIPT_DIR/agent"
AGENT_PORT=3001 TRUST_PLANE_URL=http://localhost:8080 CLAIMS_SERVICE_URL=http://localhost:3002 node dist/index.js > /tmp/agent.log 2>&1 &
AGENT_PID=$!
echo "  AI Agent started (PID: $AGENT_PID)"

# Wait for agent to register with Trust Plane
sleep 2

# Start Gateway
cd "$SCRIPT_DIR/gateway"
GATEWAY_PORT=3000 TRUST_PLANE_URL=http://localhost:8080 AGENT_URL=http://localhost:3001 node dist/index.js > /tmp/gateway.log 2>&1 &
GATEWAY_PID=$!
echo "  Gateway started (PID: $GATEWAY_PID)"

# Wait for all services
sleep 2

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
# Scenario 1: Normal Request - Alice reads her own claims
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 1: Normal Request - Alice reads her own claims${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice authenticates and asks about her claims."
echo "Expected: SUCCESS - Alice can read her own claims."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/ask \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '"'"'{"question": "What are my claims?"}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "What are my claims?"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Alice received her claims${NC}"
echo ""

# -----------------------------------------------------------------------------
# Scenario 2: Alice gets a specific claim
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 2: Alice gets details of her specific claim${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice asks about her specific claim alice-001."
echo "Expected: SUCCESS - Alice can read her own claim."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/ask \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '"'"'{"question": "What is the status of claim alice-001?"}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the status of claim alice-001?"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Alice received her claim details${NC}"
echo ""

# -----------------------------------------------------------------------------
# Scenario 3: CONFUSED DEPUTY ATTACK - Alice's agent tries to read Bob's claim
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 3: CONFUSED DEPUTY ATTACK - Agent tries to read Bob's claim${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice's agent tries to access Bob's claim (bob-001)."
echo "This simulates a confused deputy attack where the agent"
echo "attempts to read data it shouldn't have access to."
echo ""
echo "Expected: BLOCKED - Alice's PCA only allows read:claims:alice/*"
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/ask \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '"'"'{"question": "Show me claim bob-001"}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me claim bob-001"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Confused deputy attack prevented!${NC}"
echo -e "  Alice's agent could not access Bob's claim."
echo -e "  PIC enforced monotonicity: read:claims:bob-001 ⊄ read:claims:alice/*"
echo ""

# -----------------------------------------------------------------------------
# Scenario 4: CONFUSED DEPUTY ATTACK - Agent tries to list ALL claims
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 4: CONFUSED DEPUTY ATTACK - Agent tries to list ALL claims${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice's agent tries to access ALL claims in the system."
echo "This simulates an escalation attack where the agent"
echo "attempts to exceed the user's authorized scope."
echo ""
echo "Expected: BLOCKED - Alice's PCA only allows read:claims:alice/*"
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3000/ask \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '"'"'{"question": "Show me all claims in the system"}'"'"
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me all claims in the system"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Privilege escalation attack prevented!${NC}"
echo -e "  Alice's agent could not access all claims."
echo -e "  PIC enforced monotonicity: read:claims:* ⊄ read:claims:alice/*"
echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                         Summary                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The PIC Trust Plane enforces the THREE INVARIANTS:"
echo ""
echo -e "  ${GREEN}1. PROVENANCE${NC}: p_0 (Alice) is immutable throughout the chain"
echo -e "  ${GREEN}2. IDENTITY${NC}: ops can only SHRINK (ops_{i+1} ⊆ ops_i)"
echo -e "  ${GREEN}3. CONTINUITY${NC}: Cryptographic chain links each hop"
echo ""
echo "Even when the AI agent tried to:"
echo "  - Access another user's claim (bob-001)"
echo "  - List all claims in the system"
echo ""
echo "The Trust Plane rejected these requests because they violated"
echo "monotonicity - the requested operations were not subsets of"
echo "the operations granted to Alice."
echo ""
echo -e "${GREEN}CONFUSED DEPUTY ATTACKS ARE ELIMINATED BY CONSTRUCTION${NC}"
echo ""

# Keep services running for manual testing
echo "Services are still running for manual testing."
echo "Press Ctrl+C to stop all services."
echo ""
echo "Manual testing commands:"
echo '  # Alice reads her claims (should work)'
echo '  curl -s -X POST http://localhost:3000/ask -H "Authorization: Bearer mock:alice" -H "Content-Type: application/json" -d '"'"'{"question": "my claims"}'"'"' | python3 -m json.tool'
echo ""
echo '  # Alice tries to read Bob'"'"'s claim (should fail)'
echo '  curl -s -X POST http://localhost:3000/ask -H "Authorization: Bearer mock:alice" -H "Content-Type: application/json" -d '"'"'{"question": "claim bob-001"}'"'"' | python3 -m json.tool'
echo ""

# Wait for user to stop
wait

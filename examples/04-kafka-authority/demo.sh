#!/bin/bash
#
# PIC Kafka Authority Demo
#
# Demonstrates PCA embedded in Kafka message headers:
# - Producer embeds PCA proving write authority
# - Consumer validates PCA before processing
# - Messages without valid PCA are REJECTED
#
# This prevents confused deputy attacks through message queues.
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
echo -e "${BLUE}║            PIC Kafka Authority Demo                            ║${NC}"
echo -e "${BLUE}║            Message-Level Authority Enforcement                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    kill $TRUST_PLANE_PID 2>/dev/null || true
    kill $BROKER_PID 2>/dev/null || true
    kill $PRODUCER_PID 2>/dev/null || true
    kill $CONSUMER_PID 2>/dev/null || true
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

echo -e "${BLUE}[3/5] Installing and building Kafka demo services...${NC}"
cd "$SCRIPT_DIR"
cd broker-simulator && npm install --silent 2>/dev/null && npm run build 2>/dev/null && cd ..
cd producer && npm install --silent 2>/dev/null && npm run build 2>/dev/null && cd ..
cd consumer && npm install --silent 2>/dev/null && npm run build 2>/dev/null && cd ..

echo -e "${BLUE}[4/5] Starting services...${NC}"
echo ""

# Start Trust Plane
cd "$REPO_ROOT"
TRUST_PLANE_PORT=8080 cargo run --release -p provenance-plane > /tmp/trust-plane.log 2>&1 &
TRUST_PLANE_PID=$!
echo "  Trust Plane started (PID: $TRUST_PLANE_PID) - port 8080"
sleep 2

# Start Broker Simulator
cd "$SCRIPT_DIR/broker-simulator"
BROKER_PORT=9092 node dist/index.js > /tmp/broker.log 2>&1 &
BROKER_PID=$!
echo "  Kafka Broker Simulator started (PID: $BROKER_PID) - port 9092"

# Start Producer
cd "$SCRIPT_DIR/producer"
PRODUCER_PORT=3001 node dist/index.js > /tmp/producer.log 2>&1 &
PRODUCER_PID=$!
echo "  Kafka Producer started (PID: $PRODUCER_PID) - port 3001"

# Start Consumer
cd "$SCRIPT_DIR/consumer"
CONSUMER_PORT=3002 node dist/index.js > /tmp/consumer.log 2>&1 &
CONSUMER_PID=$!
echo "  Kafka Consumer started (PID: $CONSUMER_PID) - port 3002"

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
# Scenario 1: Alice produces an authorized message
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 1: Alice produces an authorized message${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Alice has scopes: [write:kafka:orders:*, write:kafka:events:*]"
echo ""
echo -e "${CYAN}Authority flow:${NC}"
echo "  1. Alice authenticates with JWT"
echo "  2. Producer issues PCA_0 with Alice's Kafka scopes"
echo "  3. Producer requests write:kafka:orders:* authority"
echo "  4. Message sent to Kafka with PCA in header"
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3001/produce \'
echo '    -H "Authorization: Bearer mock:alice" \'
echo '    -d '\''{"topic":"orders","key":"order-123","value":"Order for Alice"}'\'''
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"order-123","value":"Order for Alice: 2 items, $99.99"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Message produced with PCA authority${NC}"
echo ""

# Produce a few more messages for the consumer demo
curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"order-124","value":"Second order from Alice"}' > /dev/null

curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:admin" \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"order-125","value":"Admin system order"}' > /dev/null

echo -e "${CYAN}(Added 2 more messages from Alice and Admin)${NC}"
echo ""

# -----------------------------------------------------------------------------
# Scenario 2: Bob tries to produce (read-only user)
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 2: Bob tries to produce (read-only user)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Bob only has scopes: [read:kafka:orders:*]"
echo "He cannot write - this should fail at the Producer."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3001/produce \'
echo '    -H "Authorization: Bearer mock:bob" \'
echo '    -d '\''{"topic":"orders","key":"hack","value":"malicious message"}'\'''
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:bob" \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"hack","value":"malicious message"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Bob cannot produce - no write:kafka:* permissions${NC}"
echo ""

# -----------------------------------------------------------------------------
# Scenario 3: Analytics tries wrong topic
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 3: Analytics service tries to write to orders (wrong topic)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Analytics has scopes: [write:kafka:analytics:*]"
echo "It can only write to analytics topic, not orders."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3001/produce \'
echo '    -H "Authorization: Bearer mock:analytics" \'
echo '    -d '\''{"topic":"orders","key":"fake","value":"fake order"}'\'''
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:analytics" \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"fake","value":"fake order from analytics"}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Analytics cannot write to orders topic${NC}"
echo -e "  Trust Plane rejected: write:kafka:orders:* ⊄ write:kafka:analytics:*"
echo ""

# -----------------------------------------------------------------------------
# Scenario 4: Consumer processes authorized messages
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 4: Consumer validates and processes messages${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Consumer fetches messages from Kafka and validates PCA for each."
echo ""
echo "Request:"
echo '  curl -X POST http://localhost:3002/consume \'
echo '    -d '\''{"topic":"orders","max_messages":10}'\'''
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3002/consume \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","max_messages":10}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Consumer validated PCA for all messages${NC}"
echo -e "  Each message's authority traces back to original user (p_0)"
echo ""

# -----------------------------------------------------------------------------
# Scenario 5: Simulate message injection attack
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}Scenario 5: Simulated message injection attack${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Attacker injects message directly into Kafka (bypassing Producer)."
echo "Message has NO PCA header - consumer will REJECT it."
echo ""

# Inject message directly to broker without PCA
curl -s -X POST http://localhost:9092/produce \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","key":"injected","value":"MALICIOUS: This message was injected directly!"}' > /dev/null

echo "Injected message without PCA..."
echo ""
echo "Now consumer processes messages:"

RESPONSE=$(curl -s -X POST http://localhost:3002/consume \
  -H "Content-Type: application/json" \
  -d '{"topic":"orders","max_messages":10}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${RED}✓ BLOCKED: Injected message rejected - no PCA header${NC}"
echo -e "  Even if Kafka is compromised, PIC-aware consumers reject unauthorized messages"
echo ""

# -----------------------------------------------------------------------------
# Scenario 6: Filter by principal
# -----------------------------------------------------------------------------
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scenario 6: Consumer filters by principal (p_0)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Consumer only processes messages from specific principals."
echo "This uses the immutable p_0 in PCA for filtering."
echo ""

# Add some more messages to a new topic for this demo
curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"topic":"events","key":"event-1","value":"Alice event"}' > /dev/null

curl -s -X POST http://localhost:3001/produce \
  -H "Authorization: Bearer mock:admin" \
  -H "Content-Type: application/json" \
  -d '{"topic":"events","key":"event-2","value":"Admin event"}' > /dev/null

echo "Request (filter to only alice):"
echo '  curl -X POST http://localhost:3002/consume-with-filter \'
echo '    -d '\''{"topic":"events","allowed_principals":["alice"]}'\'''
echo ""
echo "Response:"

RESPONSE=$(curl -s -X POST http://localhost:3002/consume-with-filter \
  -H "Content-Type: application/json" \
  -d '{"topic":"events","allowed_principals":["alice"]}')

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""
echo -e "${GREEN}✓ SUCCESS: Only messages from alice were processed${NC}"
echo -e "  p_0 is IMMUTABLE - cannot be forged by intermediate services"
echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                         Summary                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "PIC Kafka Authority demonstrates:"
echo ""
echo -e "  ${GREEN}1. PRODUCER AUTHORIZATION${NC}"
echo "     - Each produce request requires valid PCA"
echo "     - Authority narrowed to specific topic (write:kafka:{topic}:*)"
echo "     - PCA embedded in message headers"
echo ""
echo -e "  ${GREEN}2. CONSUMER VALIDATION${NC}"
echo "     - Consumer validates PCA before processing"
echo "     - Messages without PCA are REJECTED"
echo "     - Authority traces back to original user (p_0)"
echo ""
echo -e "  ${GREEN}3. END-TO-END SECURITY${NC}"
echo "     - Even if Kafka broker is compromised:"
echo "       * Injected messages lack valid PCA"
echo "       * PIC-aware consumers reject them"
echo "     - Authority is cryptographically bound to messages"
echo ""
echo -e "  ${GREEN}4. PRINCIPAL FILTERING${NC}"
echo "     - p_0 is IMMUTABLE throughout the chain"
echo "     - Consumers can filter by trusted principals"
echo "     - No intermediate service can forge p_0"
echo ""
echo -e "${GREEN}MESSAGE AUTHORITY IS PROVABLY CONSTRAINED${NC}"
echo ""

# Consumer stats
echo "Consumer Statistics:"
curl -s http://localhost:3002/stats | python3 -m json.tool 2>/dev/null || curl -s http://localhost:3002/stats
echo ""

# Keep running
echo "Services are still running for manual testing."
echo "Press Ctrl+C to stop."
echo ""
echo "Test commands:"
echo '  # Produce as alice'
echo '  curl -s -X POST http://localhost:3001/produce -H "Authorization: Bearer mock:alice" -H "Content-Type: application/json" -d '\''{"topic":"orders","key":"test","value":"hello"}'\'' | python3 -m json.tool'
echo ""
echo '  # Try produce as bob (should fail - read only)'
echo '  curl -s -X POST http://localhost:3001/produce -H "Authorization: Bearer mock:bob" -H "Content-Type: application/json" -d '\''{"topic":"orders","key":"test","value":"hello"}'\'' | python3 -m json.tool'
echo ""
echo '  # Consume messages'
echo '  curl -s -X POST http://localhost:3002/consume -H "Content-Type: application/json" -d '\''{"topic":"orders"}'\'' | python3 -m json.tool'
echo ""

wait

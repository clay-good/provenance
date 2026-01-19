# AI Agent Insurance Demo

This demo shows how PIC (Provenance Identity Continuity) prevents **confused deputy attacks** in AI agent systems.

## The Problem: Confused Deputy Attacks

When an AI agent acts on behalf of a user, it has significant power to access backend services. Without proper authority tracking, the agent might:

1. **Access data it shouldn't** - Reading another user's claims
2. **Exceed user's authority** - Listing all claims when user can only see their own
3. **Be tricked by prompt injection** - Malicious prompts could instruct the agent to leak data

Traditional authorization (checking "is this user allowed?") fails because the **agent** makes the requests, not the user directly.

## The Solution: PIC Authority Chains

PIC solves this by tracking authority through a cryptographic chain:

```
User (Alice) authenticates
         │
         ▼
┌─────────────────────┐
│   Agent Gateway     │ PCA_0: ops=[read:claims:alice/*]
│   (hop 0)           │ p_0 = alice
└─────────────────────┘
         │ PoC (requesting read:claims:alice/*)
         ▼
┌─────────────────────┐
│   AI Agent Runtime  │ PCA_1: ops=[read:claims:alice/*]
│   (hop 1)           │ p_0 = alice (IMMUTABLE)
└─────────────────────┘
         │ PoC (agent tries ops=[read:claims:*]) ← ATTACK
         ▼
┌─────────────────────┐
│   Trust Plane       │ REJECTED! read:claims:* ⊄ read:claims:alice/*
│                     │ Monotonicity violation
└─────────────────────┘
```

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Gateway   │ ───► │   Agent     │ ───► │   Claims    │
│  (port 3000)│      │  (port 3001)│      │  (port 3002)│
└─────────────┘      └─────────────┘      └─────────────┘
       │                    │                    │
       │                    │                    │
       ▼                    ▼                    │
┌───────────────────────────────────────────────────────┐
│                    Trust Plane                         │
│                    (port 8080)                         │
└───────────────────────────────────────────────────────┘
```

### Components

1. **Gateway** (`gateway/`) - Entry point that:
   - Authenticates users (mock JWT)
   - Issues PCA_0 with user-scoped operations
   - Routes requests to the AI agent

2. **AI Agent** (`agent/`) - Simulated AI agent that:
   - Receives PCA from gateway
   - Calls "tools" (functions) that need authority
   - Must request successor PCA for each tool call

3. **Claims Service** (`claims-service/`) - Backend service that:
   - Stores insurance claim data
   - Validates PCA before returning data
   - Final enforcement point

4. **Trust Plane** (Rust server) - The authority service that:
   - Issues PCA_0 at federation entry
   - Processes PoC requests
   - Enforces the three PIC invariants

## Running the Demo

### Prerequisites

- Rust toolchain (rustup)
- Node.js 18+
- npm

### Quick Start

```bash
./demo.sh
```

This will:
1. Build the Trust Plane
2. Install dependencies
3. Start all services
4. Run demo scenarios showing:
   - Normal request (Alice reads her claims) ✓
   - Confused deputy attack blocked (Alice's agent tries Bob's claim) ✗
   - Privilege escalation blocked (Agent tries to list all claims) ✗

### Manual Testing

After running the demo, services stay running for manual testing:

```bash
# Alice reads her claims (should work)
curl -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "What are my claims?"}'

# Alice tries to read Bob's claim (should fail - confused deputy)
curl -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me claim bob-001"}'

# Alice tries to list all claims (should fail - privilege escalation)
curl -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me all claims in the system"}'
```

## The Three PIC Invariants

Every request is validated against these invariants:

1. **PROVENANCE**: `p_0` (origin principal) is IMMUTABLE
   - Alice's identity stays Alice throughout the chain
   - Cannot be changed by any service

2. **IDENTITY**: Operations can only SHRINK
   - `ops_{i+1} ⊆ ops_i` must always hold
   - Agent cannot request more authority than it received

3. **CONTINUITY**: Cryptographic chain links each hop
   - Each PCA contains provenance linking to predecessor
   - Signatures verified at each step

## Why This Matters for AI Agents

Traditional authorization asks: "Is this **service** allowed to do X?"

PIC asks: "Does this **request** have authority to do X, traced back to the original user?"

This means:
- Prompt injection can't elevate privileges
- Jailbroken agents can't exceed user's authority
- Multi-hop service chains maintain proper authority
- Confused deputy attacks are **eliminated by construction**

## Mock Data

The claims service has these mock claims:

| Claim ID | Owner | Type | Status |
|----------|-------|------|--------|
| alice-001 | alice | auto | approved |
| alice-002 | alice | health | pending |
| bob-001 | bob | home | approved |
| bob-002 | bob | auto | denied |
| charlie-001 | charlie | life | pending |

Only the owner of each claim should be able to access it.

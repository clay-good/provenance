# PIC Trust Plane

**Provenance Identity Continuity (PIC)** - A cryptographic authority tracking system that eliminates confused deputy attacks by construction.

---

## Attribution & Inspiration

This implementation is based on the **Provenance Identity Continuity (PIC)** theory and protocol designed by **[Nicola Gallo](https://github.com/ngallo)**.

| Resource | Link |
|----------|------|
| PIC Protocol | https://github.com/pic-protocol |
| Nicola Gallo | https://github.com/ngallo |
| Permguard | https://github.com/permguard/permguard |

The core insight of PIC is that **authority is a continuous system** where invalid states should be non-expressible which provides the theoretical foundation for this implementation. All credit for the PIC theory, the three invariants (Provenance, Identity, Continuity), and the mathematical model goes to **[Nicola Gallo](https://github.com/ngallo)** and the PIC Protocol team.

---

## The Problem: Confused Deputy Attacks

In distributed systems and AI agent architectures, a **confused deputy attack** occurs when a privileged service is tricked into misusing its authority on behalf of a less-privileged caller.

### Traditional Authorization Fails

```
Traditional Auth: "Is Service A allowed to read claims?"
Answer: YES (Service A has broad access)

But wait... Service A is acting on behalf of Alice,
who should only read HER claims, not all claims!
```

The root cause: traditional authorization checks the **service's** permissions, not the **request's** authority traced back to its origin.

### Real-World Scenarios

| Scenario | Traditional Auth | What Goes Wrong |
|----------|-----------------|-----------------|
| AI Agent | Agent has read:claims:* | Prompt injection causes data leak |
| Microservices | Each service has its own permissions | Downstream services can't verify upstream authority |
| Message Queues | Producer signs messages | Consumer can't verify end-user authority |

## The Solution: PIC Authority Chains

PIC tracks authority through a cryptographic chain of **Proof of Causal Authority (PCA)**:

```
User (Alice) authenticates at federation entry
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│  PCA_0 (issued by Trust Plane)                              │
│  ─────────────────────────────────────────                  │
│  p_0: alice           ← Origin principal (IMMUTABLE)        │
│  ops: [read:claims:alice/*]  ← Alice's actual authority     │
│  hop: 0                                                     │
│  signature: <CAT signature>                                 │
└─────────────────────────────────────────────────────────────┘
                    │
                    │ Service A requests narrower ops
                    ▼
┌─────────────────────────────────────────────────────────────┐
│  PCA_1 (successor PCA)                                      │
│  ─────────────────────────────────────────                  │
│  p_0: alice           ← SAME as PCA_0 (cannot change!)      │
│  ops: [read:claims:alice/claim-123]  ← Narrower scope       │
│  hop: 1                                                     │
│  provenance: {link to PCA_0, signatures}                    │
└─────────────────────────────────────────────────────────────┘
```

## The Three PIC Invariants

Every successor PCA is validated against these invariants:

### 1. PROVENANCE: Origin Principal is Immutable

```rust
// p_0 is ALWAYS copied from predecessor, never from request
successor.p_0 = predecessor.p_0;  // Hardcoded, cannot be overridden
```

**Attack prevented**: Attacker cannot impersonate another user by modifying p_0.

### 2. IDENTITY: Operations Can Only Shrink

```rust
// ops_{i+1} ⊆ ops_i must always hold
if !predecessor.ops.contains_all(&requested_ops) {
    return Err(MonotonicityViolation);
}
```

**Attack prevented**: Services cannot escalate privileges or access unauthorized resources.

### 3. CONTINUITY: Cryptographic Chain Links Each Hop

```rust
// Each PCA contains provenance proving link to predecessor
struct Provenance {
    cat_kid: String,      // Trust Plane key ID
    cat_sig: Vec<u8>,     // Trust Plane signature
    executor_kid: String, // Executor key ID
    executor_sig: Vec<u8> // Executor signature on PoC
}
```

**Attack prevented**: Chain cannot be forged or tampered with.

## Before vs After: Traditional Auth vs PIC

### Before (Traditional Authorization)

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Gateway   │ ───► │   Service   │ ───► │   Database  │
│             │      │             │      │             │
│ Checks:     │      │ Checks:     │      │ Checks:     │
│ "Is Alice   │      │ "Is Service │      │ "Is Service │
│  logged in?"│      │  A allowed?"│      │  B allowed?"│
└─────────────┘      └─────────────┘      └─────────────┘

Problem: Each service checks its own permissions, not Alice's authority.
         If Service A is compromised, it can access ANY data it has access to.
```

### After (PIC Authority Chains)

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Gateway   │ ───► │   Service   │ ───► │   Database  │
│   (hop 0)   │      │   (hop 1)   │      │   (hop 2)   │
│             │      │             │      │             │
│ PCA_0:      │      │ PCA_1:      │      │ PCA_2:      │
│ p_0=alice   │      │ p_0=alice   │      │ p_0=alice   │
│ ops=[r:*]   │      │ ops=[r:a/*] │      │ ops=[r:a/1] │
└─────────────┘      └─────────────┘      └─────────────┘

Solution: Authority traced back to Alice at every hop.
          Even if Service A is compromised, it can ONLY access
          what Alice is authorized to access.
```

## Architecture

```
                            ┌──────────────────────────────────┐
                            │         Trust Plane (CAT)         │
                            │                                   │
                            │  - Issues PCA_0 at entry         │
                            │  - Processes PoC requests        │
                            │  - Enforces PIC invariants       │
                            │  - Manages key registry          │
                            └──────────────────────────────────┘
                                          ▲
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
            ▼                             ▼                             ▼
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│  Federation Bridge  │      │    Executor (SDK)   │      │   Resource Server   │
│                     │      │                     │      │                     │
│  - JWT validation   │      │  - Builds PoC       │      │  - Validates PCA    │
│  - API key auth     │      │  - Requests PCA     │      │  - Enforces ops     │
│  - OIDC providers   │      │  - Forwards chain   │      │  - Logs violations  │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
```

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `provenance-core` | Rust | Core types: PCA, PoC, crypto, operations |
| `provenance-plane` | Rust | Trust Plane HTTP server (CAT service) |
| `provenance-bridge` | Rust | Federation bridge for external credentials |
| `@provenance/sdk` | TypeScript | SDK with Express middleware |

## Quick Start

### Build and Test

```bash
# Build all crates
cargo build --workspace

# Run all tests (133 tests)
cargo test --workspace

# Start Trust Plane server
cargo run -p provenance-plane
```

### Test Endpoints

```bash
# Health check
curl http://localhost:8080/health

# Readiness (includes CAT key info)
curl http://localhost:8080/ready
```

## Demo It! (Prove the Value)

We provide five working demos to prove PIC's value. Each demonstrates confused deputy prevention in different architectures.

### Demo 1: AI Agent (Insurance Claims) - **Primary Demo**

This is the most compelling demo for AI safety. Shows an insurance claims AI agent that CANNOT access data beyond the user's authority - even if the agent tries.

```bash
cd examples/02-ai-agent-insurance
./demo.sh
```

**What it shows:**
| Scenario | Action | Result |
|----------|--------|--------|
| Normal | Alice asks "What are my claims?" | ✓ SUCCESS - Returns Alice's claims |
| Normal | Alice asks for claim alice-001 | ✓ SUCCESS - Returns her claim |
| **Attack** | Agent tries to read claim bob-001 | ✗ BLOCKED - Monotonicity violation |
| **Attack** | Agent tries to list ALL claims | ✗ BLOCKED - ops not subset of granted |

**The key insight**: Alice's PCA grants `read:claims:alice/*`. When the agent tries to read `bob-001`, the Trust Plane rejects it because `read:claims:bob-001 ⊄ read:claims:alice/*`.

### Demo 2: Microservice Chain (Authority Narrowing)

Shows how authority narrows as it passes through a service chain. **This demo is fully working.**

```bash
cd examples/01-microservice-chain
./demo.sh
```

**What it shows:**
```
User (Alice) → Gateway → Archive → Storage
                 ↓          ↓          ↓
PCA_0:       ops=[read:*, write:archive:*, write:storage:*]
PCA_1:       ops=[write:archive:*, write:storage:*]  ← NARROWED
PCA_2:       ops=[write:storage:*]                   ← NARROWED AGAIN
```

**Key security properties demonstrated:**
| Scenario | What Happens |
|----------|--------------|
| Alice uploads | ✓ SUCCESS - Authority chain validates through all hops |
| Bob tries to upload | ✗ BLOCKED - MONOTONICITY_VIOLATION (Bob lacks write ops) |
| Compromised Archive | ✗ CANNOT escalate - Can only delegate what it received |

Even if Archive is compromised, it CANNOT give Storage extra permissions.

### Demo 3: Keycloak OAuth Token Exchange (RFC 8693)

Extends OAuth Token Exchange with PIC authority continuity. Shows how Keycloak tokens map to PCA operations and how provenance is preserved through token exchange flows — similar to how WIMSE extended OAuth for workload identity.

```bash
cd examples/03-keycloak-oauth-exchange
./demo.sh
```

**Requires Docker** (for Keycloak).

**What it shows:**
| Scenario | Action | Result |
|----------|--------|--------|
| Normal flow | Alice accesses her own claim | ✓ SUCCESS - PCA chain with p_0=alice |
| Provenance preserved | Inspect p_0 after token exchange | ✓ p_0=alice, not gateway service |
| **Confused deputy** | Alice's token for Bob's claim | ✗ BLOCKED - `read:claims:bob/* ⊄ read:claims:alice/*` |
| **Cross-user access** | Bob's token for Alice's claim | ✗ BLOCKED - `read:claims:alice/* ⊄ read:claims:bob/*` |

**The key insight**: The RFC 8693 `act` claim naturally maps to PIC's provenance chain. After token exchange, `p_0` is still the original human user — token exchange cannot launder identity.

### Demo 4: Kafka Message Authority

Shows PCA embedded in Kafka message headers for end-to-end authority.

```bash
cd examples/04-kafka-authority
./demo.sh
```

**What it shows:**
- Producer embeds PCA in message headers
- Consumer validates PCA before processing
- Messages without valid PCA are rejected
- Unauthorized topic access is blocked

### Demo 5: Federation

```bash
cd examples/05-federation
./demo.sh
```

**Key takeaways:**
1. Trust Planes can register each other's CAT public keys
2. PCAs from federated Trust Planes can be verified
3. Authority flows securely across organizational boundaries
4. Unknown or unregistered CATs are rejected
5. PIC invariants (p_0 immutability, ops monotonicity) preserved

### Manual Testing

After running any demo, services stay running. Test manually:

```bash
# Health check
curl http://localhost:8080/health

# Alice reads her claims (should work)
curl -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "What are my claims?"}'

# Alice tries to read Bob's claim (should fail with 403)
curl -X POST http://localhost:3000/ask \
  -H "Authorization: Bearer mock:alice" \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me claim bob-001"}'
```

### Run Attack Tests (Prove Security)

See all 14 attack scenarios blocked:

```bash
cargo test -p provenance-plane -- attacks --nocapture
```

Each test demonstrates a specific attack vector that PIC prevents by construction.

### Docker Deployment

```bash
cd deploy/docker

# Standalone Trust Plane
docker-compose -f docker-compose.standalone.yml up

# Full demo environment
docker-compose up
```

## API Reference

### POST /v1/pca/issue

Issue PCA_0 at federation entry.

```json
{
  "credential": "Bearer <jwt>",
  "credential_type": "jwt",
  "requested_ops": ["read:claims:*"],
  "executor": { "service": "gateway" }
}
```

### POST /v1/poc/process

Process PoC and issue successor PCA.

```json
{
  "poc": "<base64-encoded-signed-poc>",
  "predecessor_pca": "<base64-encoded-signed-pca>"
}
```

### POST /v1/keys/executor

Register executor public key.

```json
{
  "kid": "executor-1",
  "public_key": "<base64-encoded-public-key>"
}
```

## Examples

| Example | Description |
|---------|-------------|
| `01-microservice-chain` | Gateway → Archive → Storage with authority narrowing |
| `02-ai-agent-insurance` | AI agent confused deputy prevention |
| `03-keycloak-oauth-exchange` | OAuth Token Exchange (RFC 8693) with PIC authority continuity via Keycloak |
| `04-kafka-authority` | Kafka message authority with PCA headers |
| `05-federation` | Cross-organization Trust Plane federation |
| `06-keycloak-pic-spi` | Server-side PIC via Keycloak SPI — RFC 8693 token exchange with embedded PIC claims |

## Security Properties

### Attacks Prevented

| Attack | How PIC Prevents It |
|--------|---------------------|
| Confused Deputy | Authority traced to origin, not service |
| Privilege Escalation | Monotonicity check rejects broader ops |
| Identity Spoofing | p_0 is cryptographically immutable |
| Chain Forgery | COSE signatures at each hop |
| Cross-Tenant Access | ops scope prevents tenant boundary crossing |

### Test Coverage (133 tests)

- **Unit tests**: Core types, crypto, operations (78 tests)
- **Property-based tests**: Verify invariants hold for arbitrary inputs (17 tests)
- **Integration tests**: Full chain validation, key registry (24 tests)
- **Attack scenario tests**: 14 specific attack patterns blocked

## Project Structure

```
provenance/
├── crates/
│   ├── provenance-core/      # Core types and crypto
│   ├── provenance-plane/     # Trust Plane server
│   └── provenance-bridge/    # Federation bridge
├── keycloak-pic-spi/         # Keycloak SPI (Java 17, Maven)
│   ├── src/main/java/        # 23 implementation classes
│   ├── src/test/java/        # 20 test classes
│   ├── pom.xml               # Keycloak 26.0, Java 17
│   └── Dockerfile            # Multi-stage production build
├── sdks/
│   └── typescript/           # TypeScript SDK
├── examples/
│   ├── 01-microservice-chain/
│   ├── 02-ai-agent-insurance/
│   ├── 03-keycloak-oauth-exchange/
│   ├── 04-kafka-authority/
│   ├── 05-federation/
│   └── 06-keycloak-pic-spi/  # Server-side PIC demo
└── deploy/
    └── docker/               # Docker deployment
```

## Development

### Prerequisites

- Rust 1.75+
- Node.js 18+ (for TypeScript SDK and examples)
- Docker (for deployment)

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p provenance-core
cargo test -p provenance-plane
cargo test -p provenance-bridge

# TypeScript SDK tests
cd sdks/typescript && npm test
```

### Code Quality

The codebase maintains zero warnings policy:
- `cargo build --workspace` produces no warnings
- `cargo clippy --workspace` passes
- All tests pass without warnings

---

## Integration Guide

This implementation can be integrated into existing systems at multiple levels:

### 1. Gateway/API Integration

Add PIC at your federation entry point to issue PCA_0 for authenticated users:

```typescript
import { TrustPlaneClient } from '@provenance/sdk';

const trustPlane = new TrustPlaneClient('http://trust-plane:8080');

// At authentication, issue PCA_0 with user-scoped authority
const pca0 = await trustPlane.issuePca({
  credential: userJwt,
  credential_type: 'jwt',
  ops: [`read:data:${userId}/*`, `write:data:${userId}/*`],
  executor_binding: { service: 'gateway', user_id: userId }
});

// Forward PCA to downstream services
res.setHeader('X-PIC-PCA', pca0.pca);
```

### 2. Service Mesh Integration

For Kubernetes/Istio environments, PIC can be enforced at the mesh level:

```yaml
# Envoy filter to validate PCA on every request
# (Future: Istio WASM plugin)
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: pic-authority-filter
spec:
  workloadSelector:
    labels:
      pic-enabled: "true"
  configPatches:
    - applyTo: HTTP_FILTER
      patch:
        operation: INSERT_BEFORE
        value:
          name: pic.authority_validator
          # WASM module validates X-PIC-PCA header
```

### 3. Message Queue Integration

Embed PCA in message headers for end-to-end authority:

```typescript
// Producer: embed PCA in message
await kafka.send({
  topic: 'orders',
  messages: [{
    key: orderId,
    value: JSON.stringify(order),
    headers: { 'X-PIC-PCA': pca.pca }
  }]
});

// Consumer: validate before processing
const pca = message.headers['X-PIC-PCA'];
if (!validatePca(pca, `write:orders:${message.key}`)) {
  reject(message); // Authority violation
}
```

### 4. AI Agent Framework Integration

For LangChain, AutoGPT, or custom agent frameworks:

```typescript
class PicAwareTool {
  constructor(private trustPlane: TrustPlaneClient) {}

  async execute(action: string, pca: SignedPca) {
    // Request narrowed authority for this specific action
    const poc = await createAndSignPoc(pca, {
      ops: [action],
      executor: { tool: this.name }
    });

    const successorPca = await this.trustPlane.processPoc({
      poc: poc,
      predecessor_pca: pca
    });

    // If we get here, authority was granted
    return this.performAction(action, successorPca);
  }
}
```

---

## Federation: Cross-Organization Authority

PIC enables secure authority delegation across organizational boundaries through **Trust Plane Federation**.

### How Federation Works

```
┌─────────────────────┐          ┌─────────────────────┐
│  Trust Plane A      │  ◄────►  │  Trust Plane B      │
│  (Org A)            │          │  (Org B)            │
│                     │          │                     │
│  CAT Key: tp-a-xxx  │          │  CAT Key: tp-b-yyy  │
│  Knows: tp-b-yyy    │          │  Knows: tp-a-xxx    │
└─────────────────────┘          └─────────────────────┘
         │                                │
         │                                │
         ▼                                ▼
   Services in Org A              Services in Org B
   can verify PCAs from           can verify PCAs from
   both Trust Planes              both Trust Planes
```

### Federation API

```bash
# Register a federated Trust Plane's CAT key
curl -X POST http://localhost:8080/v1/federation/cats \
  -H "Content-Type: application/json" \
  -d '{
    "kid": "trust-plane-partner-xyz",
    "public_key": "<base64-ed25519-public-key>",
    "name": "Partner Org Trust Plane",
    "endpoint": "https://partner.example.com/trust-plane"
  }'

# List registered federated CATs
curl http://localhost:8080/v1/federation/cats

# Verify a PCA from a federated Trust Plane
curl -X POST http://localhost:8080/v1/federation/verify \
  -H "Content-Type: application/json" \
  -d '{"pca": "<base64-encoded-signed-pca>"}'

# Discover a Trust Plane's CAT key from its endpoint
curl -X POST http://localhost:8080/v1/federation/discover \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "https://partner.example.com/trust-plane"}'
```

### Federation Security Properties

| Property | How It's Enforced |
|----------|-------------------|
| CAT Key Validation | Only registered federated CATs are trusted |
| PIC Invariants | All three invariants preserved across federation |
| Unknown CAT Rejection | PCAs from unregistered Trust Planes are rejected |
| Cross-Org Authority | p_0 origin principal preserved across organization boundaries |

### Demo 5: Federation (Cross-Organization)

```bash
cd examples/05-federation
./demo.sh
```

**What it shows:**
- Two Trust Planes register each other's CAT keys
- PCA from Trust Plane A can be verified by Trust Plane B
- Services in different organizations can validate cross-org authority chains
- Unknown or unregistered CATs are rejected

### Demo 6: Keycloak PIC SPI (Server-Side PIC)

```bash
cd examples/06-keycloak-pic-spi
./demo.sh
```

**Requires Docker** (for Keycloak + Trust Plane) and **Maven** (for SPI build).

**What it shows:**

| Scenario | Action | Result |
|----------|--------|--------|
| Normal flow | Alice token exchange with PIC token type | pic+jwt with embedded PIC claims |
| Provenance | Inspect p_0 in pic_provenance | p_0 = alice (not service account) |
| Scope narrowing | Exchange with narrowed scope | pic_ops narrowed to requested scope |
| **Confused deputy** | Alice requests Bob's ops | **BLOCKED** — empty intersection |
| Introspection | POST /realms/pic-demo/pic/introspect | active=true, p_0, pic_ops, chain_length |
| Audit trail | Inspect pic_chain | hop=0, executor, pca_hash, cat_kid |

**Key insight**: PIC works transparently at the IdP level. Standard OAuth clients get authority continuity without any code changes — the Keycloak SPI does everything.

---

## Keycloak PIC SPI — Deep Dive

The Keycloak PIC SPI is a server-side integration that embeds PIC authority continuity directly into Keycloak's OAuth 2.0 Token Exchange (RFC 8693). Instead of requiring every service to integrate a PIC SDK and contact the Trust Plane independently, the Identity Provider itself enforces all three PIC invariants during token exchange. The result is a self-contained `pic+jwt` token that carries provenance, scoped operations, and a cryptographic audit trail — no client-side changes needed.

### How It Works — System Design

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         KEYCLOAK PIC SPI — TOKEN EXCHANGE FLOW                   │
│                                                                                  │
│                                                                                  │
│  ┌──────────┐          ┌──────────────────────────────────────┐          ┌──────────────┐
│  │          │    1     │              KEYCLOAK 26.0            │    3     │              │
│  │  OAuth   │ ────────►│                                      │ ────────►│  Trust Plane │
│  │  Client  │  POST    │  ┌────────────────────────────────┐  │  POST    │   (Rust)     │
│  │          │  /token   │  │        PIC SPI (Java)          │  │  /v1/    │              │
│  │          │          │  │                                │  │  pca/    │  Enforces:   │
│  │          │          │  │  ┌──────────┐ ┌─────────────┐  │  │  issue   │  - p_0       │
│  │          │          │  │  │Principal │ │ OpsResolver │  │  │         │    immutable  │
│  │          │          │  │  │Extractor │ │(intersection│  │  │         │  - ops ⊆     │
│  │          │          │  │  │(p_0 from │ │ + wildcard) │  │  │         │    predecessor│
│  │          │          │  │  │act chain)│ │             │  │  │         │  - Signs PCA │
│  │          │          │  │  └──────────┘ └─────────────┘  │  │         │              │
│  │          │          │  │  ┌──────────┐ ┌─────────────┐  │  │         │              │
│  │          │          │  │  │TrustPlane│ │ Audit Event │  │  │         │              │
│  │          │    4     │  │  │ Client   │ │  Listener   │  │  │    4    │              │
│  │          │ ◄────────│  │  │(HTTP)    │ │(PIC events) │  │  │ ◄───────│              │
│  │          │  pic+jwt │  │  └──────────┘ └─────────────┘  │  │  PCA    │              │
│  │          │          │  └────────────────────────────────┘  │  signed  │              │
│  └──────────┘          │                                      │         └──────────────┘
│                        │  ┌────────────────────────────────┐  │
│                        │  │   Additional SPI Components     │  │
│                        │  │                                │  │
│                        │  │  • PicRealmResource             │  │
│                        │  │    GET /pic/well-known          │  │
│                        │  │    POST /pic/introspect         │  │
│                        │  │                                │  │
│                        │  │  • PicAdminResource             │  │
│                        │  │    Key mgmt, config updates     │  │
│                        │  │                                │  │
│                        │  │  • PicOpsProtocolMapper         │  │
│                        │  │    Maps user attrs → pic_ops    │  │
│                        │  └────────────────────────────────┘  │
│                        └──────────────────────────────────────┘
│                                                                                  │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                                                                                  │
│  STEP-BY-STEP FLOW:                                                              │
│                                                                                  │
│  1. Client sends RFC 8693 token exchange request to Keycloak:                    │
│     POST /realms/{realm}/protocol/openid-connect/token                           │
│       grant_type=urn:ietf:params:oauth:grant-type:token-exchange                 │
│       subject_token=<alice's JWT>                                                │
│       requested_token_type=urn:ietf:params:oauth:token-type:pic_token            │
│       scope=read:claims:alice/*                                                  │
│                                                                                  │
│  2. PIC SPI intercepts the exchange (supports() returns true) and:               │
│     a. Extracts p_0 from the subject token's act claim chain                     │
│     b. Loads Alice's authorized ops from user attribute (pic_ops)                │
│     c. Computes effective ops = intersection(authorized, requested)              │
│     d. If intersection is empty → 403 (confused deputy BLOCKED)                 │
│                                                                                  │
│  3. SPI calls Trust Plane to issue a PCA (Proof of Causal Authority):            │
│     POST /v1/pca/issue { credential, ops, executor_binding }                     │
│     Trust Plane validates invariants, signs the PCA, returns it                  │
│                                                                                  │
│  4. SPI builds a pic+jwt response containing:                                    │
│     • pic_provenance: { p_0, pca_0_hash, cat_kid, hop, trust_plane }            │
│     • pic_ops: [ effective operations ]                                          │
│     • pic_chain: [ { hop, executor, ops, pca_hash, cat_kid } ]                  │
│     Signs with Keycloak's realm key (JOSE header typ: "pic+jwt")                │
│                                                                                  │
│  5. Client receives a self-contained pic+jwt — no separate PCA header needed     │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Multi-Hop Token Exchange (Service-to-Service Delegation)

When a service receives a `pic+jwt` and needs to delegate further, the SPI detects the predecessor PCA and calls `processPoc()` instead of `issuePca()`, extending the chain:

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Alice   │     │   Service A  │     │   Service B  │     │   Database   │
│ (human)  │     │   (hop 0)    │     │   (hop 1)    │     │   (hop 2)    │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │                    │
     │  1. Login +      │                    │                    │
     │  token exchange  │                    │                    │
     │ ────────────────►│                    │                    │
     │                  │                    │                    │
     │  pic+jwt         │                    │                    │
     │  p_0=alice       │                    │                    │
     │  ops=[r:*,w:*]   │                    │                    │
     │ ◄────────────────│                    │                    │
     │                  │                    │                    │
     │                  │  2. Re-exchange    │                    │
     │                  │  pic+jwt (hop 0)   │                    │
     │                  │  scope=r:alice/*   │                    │
     │                  │ ──────────────────►│                    │
     │                  │                    │                    │
     │                  │  pic+jwt (hop 1)   │                    │
     │                  │  p_0=alice ◄──── SAME (immutable)      │
     │                  │  ops=[r:alice/*] ◄─ NARROWED            │
     │                  │ ◄──────────────────│                    │
     │                  │                    │                    │
     │                  │                    │  3. Re-exchange    │
     │                  │                    │  scope=r:alice/1   │
     │                  │                    │ ──────────────────►│
     │                  │                    │                    │
     │                  │                    │  pic+jwt (hop 2)   │
     │                  │                    │  p_0=alice ◄── STILL ALICE
     │                  │                    │  ops=[r:alice/1]◄─ NARROWED AGAIN
     │                  │                    │ ◄──────────────────│
     │                  │                    │                    │
```

At every hop, the PIC invariants guarantee:
- **p_0 stays Alice** — identity cannot be laundered through token exchange
- **ops can only shrink** — no service can escalate beyond what it received
- **chain is cryptographically signed** — every hop is auditable back to the Trust Plane

### SPI Module Architecture

```
keycloak-pic-spi/
├── src/main/java/com/provenance/keycloak/pic/
│   ├── PicConstants.java                  # URNs, claim names, attribute keys
│   │
│   ├── exchange/                          # Core token exchange (RFC 8693 + PIC)
│   │   ├── PicTokenExchangeProvider.java  # Main exchange logic (767 lines)
│   │   ├── PicTokenExchangeProviderFactory.java  # SPI factory + lifecycle
│   │   ├── OpsResolver.java              # Operation intersection + wildcards
│   │   ├── PrincipalExtractor.java       # p_0 from act claim chains
│   │   └── PicExchangeException.java     # Typed errors → OAuth error codes
│   │
│   ├── trustplane/                        # Trust Plane HTTP client
│   │   ├── TrustPlaneClient.java         # Thread-safe HTTP client
│   │   ├── PcaIssuanceResult.java        # PCA result DTO + SHA-256 hash
│   │   ├── TrustPlaneException.java      # Error classification
│   │   └── TrustPlaneStatus.java         # Health check status
│   │
│   ├── resource/                          # Public realm endpoints
│   │   ├── PicRealmResource.java         # /pic/well-known, /pic/introspect
│   │   ├── PicRealmResourceProvider.java
│   │   └── PicRealmResourceProviderFactory.java
│   │
│   ├── admin/                             # Admin console endpoints
│   │   ├── PicAdminResource.java         # Key management, config
│   │   ├── PicAdminResourceProvider.java
│   │   └── PicAdminResourceProviderFactory.java
│   │
│   ├── audit/                             # PIC event listener
│   │   ├── PicEventListenerProvider.java  # Audit logging
│   │   ├── PicEventListenerProviderFactory.java
│   │   └── PicAuditEvent.java            # Audit event model
│   │
│   ├── mapper/                            # Protocol mapper
│   │   └── PicOpsProtocolMapper.java     # Maps user attrs → pic_ops claim
│   │
│   └── model/                             # Data models
│       ├── PicRealmConfig.java           # Realm configuration
│       ├── PicProvenanceClaim.java       # pic_provenance claim structure
│       └── PicChainEntry.java            # pic_chain entry structure
│
├── src/main/resources/META-INF/services/  # 5 SPI registrations
│   ├── org.keycloak.protocol.oidc.TokenExchangeProviderFactory
│   ├── org.keycloak.services.resource.RealmResourceProviderFactory
│   ├── org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory
│   ├── org.keycloak.events.EventListenerProviderFactory
│   └── org.keycloak.protocol.ProtocolMapper
│
├── src/test/java/                         # 20 test classes
│   └── com/provenance/keycloak/pic/
│       ├── exchange/                      # Unit tests for exchange logic
│       ├── trustplane/                    # Trust Plane client tests
│       ├── resource/                      # Endpoint tests
│       ├── admin/                         # Admin endpoint tests
│       ├── audit/                         # Audit tests
│       ├── mapper/                        # Mapper tests
│       ├── model/                         # Model tests
│       └── integration/                   # Full E2E with Testcontainers
│
├── pom.xml                                # Maven build (Keycloak 26.0, Java 17)
└── Dockerfile                             # Multi-stage production build
```

### Client-Side vs Server-Side PIC

This diagram shows why the Keycloak SPI approach is preferred for most deployments:

```
BEFORE (Client-Side PIC — Example 03):          AFTER (Server-Side PIC — Example 06):

┌─────────┐  ┌─────────┐  ┌─────────┐          ┌─────────┐  ┌─────────┐  ┌─────────┐
│Service A│  │Service B│  │Service C│          │Service A│  │Service B│  │Service C│
│         │  │         │  │         │          │         │  │         │  │         │
│ PIC SDK │  │ PIC SDK │  │ PIC SDK │          │ (no PIC │  │ (no PIC │  │ (no PIC │
│ ┌─────┐ │  │ ┌─────┐ │  │ ┌─────┐ │          │  code)  │  │  code)  │  │  code)  │
│ │Trust│ │  │ │Trust│ │  │ │Trust│ │          │         │  │         │  │         │
│ │Plane│ │  │ │Plane│ │  │ │Plane│ │          └────┬────┘  └────┬────┘  └────┬────┘
│ │Call │ │  │ │Call │ │  │ │Call │ │               │            │            │
│ └──┬──┘ │  │ └──┬──┘ │  │ └──┬──┘ │               │            │            │
└────┼────┘  └────┼────┘  └────┼────┘               │            │            │
     │            │            │               ┌─────┴────────────┴────────────┴─────┐
     │            │            │               │                                     │
     ▼            ▼            ▼               │        KEYCLOAK + PIC SPI           │
┌────────────────────────────────┐             │                                     │
│         Trust Plane            │             │  Single integration point:           │
│  (3 separate connections)      │             │  SPI calls Trust Plane once          │
└────────────────────────────────┘             │  per token exchange                  │
                                               │                                     │
Every service needs PIC SDK,                   └──────────────┬──────────────────────┘
config, Trust Plane connection.                               │
N services = N integrations.                                  ▼
                                               ┌────────────────────────────────┐
                                               │         Trust Plane            │
                                               │    (1 connection from SPI)     │
                                               └────────────────────────────────┘

                                               Zero service code changes.
                                               1 SPI JAR = PIC for all services.
```

### Security Model

```
┌──────────────────────────────────────────────────────────────────────┐
│                    PIC SECURITY GUARANTEES                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INVARIANT 1 — PROVENANCE (p_0 immutability)                        │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  Token exchange: Alice → Service A → Service B          │        │
│  │                                                         │        │
│  │  Standard OAuth:  sub=alice → sub=serviceA → sub=svcB   │        │
│  │                   (identity laundered!)                  │        │
│  │                                                         │        │
│  │  PIC SPI:         p_0=alice → p_0=alice → p_0=alice     │        │
│  │                   (origin ALWAYS traceable)              │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│  INVARIANT 2 — IDENTITY (monotonic ops narrowing)                   │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  Alice's authorized ops: [read:claims:alice/*,           │        │
│  │                            write:claims:alice/*]         │        │
│  │                                                         │        │
│  │  hop 0 → ops=[read:claims:alice/*, write:claims:alice/*]│        │
│  │  hop 1 → ops=[read:claims:alice/*]          ← narrowed  │        │
│  │  hop 2 → ops=[read:claims:alice/claim-001]  ← narrowed  │        │
│  │                                                         │        │
│  │  BLOCKED: ops=[read:claims:bob/*]  ← not subset of hop0│        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│  INVARIANT 3 — CONTINUITY (cryptographic chain)                     │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  pic_chain: [                                           │        │
│  │    { hop:0, executor:"gateway",  pca_hash:"a3f...",     │        │
│  │      ops:["r:*","w:*"], cat_kid:"demo-tp" },            │        │
│  │    { hop:1, executor:"service-a", pca_hash:"7bc...",    │        │
│  │      ops:["r:alice/*"], cat_kid:"demo-tp" }             │        │
│  │  ]                                                      │        │
│  │                                                         │        │
│  │  Every hop is signed by the Trust Plane (CAT).          │        │
│  │  Chain cannot be forged, reordered, or tampered with.   │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│  FAIL-CLOSED BY DEFAULT                                             │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  Trust Plane unreachable? → Exchange FAILS (503)        │        │
│  │  pic_fail_open=true?      → WARNING: issues standard    │        │
│  │                              JWT without PIC claims      │        │
│  │                              (development only!)         │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### PermGuard Integration Point

Federation enables integration with policy engines like [PermGuard](https://github.com/permguard/permguard):

```
┌─────────────────────────────────────────────────────────────┐
│                    Request Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User authenticates → PermGuard evaluates policies        │
│                          ↓                                   │
│  2. PermGuard returns allowed ops: [read:claims:alice/*]    │
│                          ↓                                   │
│  3. Trust Plane issues PCA_0 with those ops                 │
│                          ↓                                   │
│  4. PIC chain ensures ops can ONLY shrink from there        │
│                                                              │
└─────────────────────────────────────────────────────────────┘

PermGuard = "What CAN this identity do?" (Policy Decision Point)
PIC       = "What DID this identity delegate?" (Authority Chain)
```

**They are complementary, not redundant:**
- PermGuard determines INITIAL authority from policies
- PIC ensures authority can NEVER escalate beyond that initial grant

---

## Building on PIC Theory

According to PIC theory, this implementation can be extended in several directions:

### Proof of Causal Challenge (PCC)

The PIC spec defines an optional challenge-response mechanism for stronger attestation:

```
┌─────────────┐                    ┌─────────────┐
│  Executor   │ ──── PoC ────────► │ Trust Plane │
│             │ ◄─── PCC ───────── │    (CAT)    │
│             │ ──── Response ───► │             │
│             │ ◄─── PCA_{i+1} ─── │             │
└─────────────┘                    └─────────────┘
```

**Status**: RECOMMENDED per spec, not yet implemented. Would add replay protection and real-time attestation.

### TEE Attestation Integration

PIC supports Trusted Execution Environment attestation in the PoC:

```rust
struct Attestation {
    tee_type: TeeType,      // SGX, SEV, TrustZone, Nitro
    evidence: Vec<u8>,      // Platform-specific evidence
    measurements: Vec<u8>,  // Code measurements
}
```

**Status**: Types defined, attestation validation not yet implemented. Would enable hardware-backed authority verification.

### Governance Constraints (PolicyBind Integration)

PIC allows constraints to be attached to PCAs for governance:

```rust
struct Constraints {
    temporal: Option<TemporalConstraints>,  // Valid time windows
    environment: Option<EnvironmentConstraints>, // Geo, network
    budget: Option<BudgetConstraints>,      // Rate limits, quotas
    custom: HashMap<String, Value>,         // Extensible
}
```

**Integration point**: [PolicyBind](https://github.com/clay-good/policybind) can provide AI governance constraints that get embedded in PCAs.

### Federation Bridge Extensions

The Federation Bridge can be extended with additional credential handlers:

| Handler | Status | Description |
|---------|--------|-------------|
| JWT/OIDC | ✓ Implemented | Standard OAuth2/OIDC flows |
| JWT Token Exchange | ✓ Implemented | RFC 8693 with `act` claim traversal and `pic_ops` extraction |
| API Key | ✓ Implemented | MFA-validated API keys |
| SPIFFE/SPIRE | Planned | Workload identity |
| mTLS | Planned | Certificate-based identity |
| Custom | Extensible | Implement `CredentialHandler` trait |

**Integration point**: [Qiuth](https://github.com/clay-good/qiuth) (MFA for API keys) can serve as a Federation Bridge backend.

---

## Acknowledgments

- **[Nicola Gallo](https://github.com/ngallo)** - Creator of PIC theory and protocol
- **[PIC Protocol](https://github.com/pic-protocol)** - Theoretical foundation and specifications
- The confused deputy problem was first identified by Norm Hardy in 1988

> "The key insight is that authority is not a property of a principal, but of a request chain. PIC makes this mathematically precise." - Nicola Gallo 

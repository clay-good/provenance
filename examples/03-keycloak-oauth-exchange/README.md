# Keycloak OAuth Token Exchange + PIC Demo

This demo shows how **PIC (Provenance Identity Continuity)** extends **OAuth Token Exchange (RFC 8693)** with authority continuity — similar to how WIMSE extended OAuth for workload identity, PIC extends it for cryptographic authority tracking.

## The Problem: Token Exchange Launders Identity

OAuth Token Exchange (RFC 8693) allows a service to exchange a user's token for a new token scoped to a different audience. This is useful for microservice architectures, but it creates a security gap:

```
Alice authenticates → Gateway → exchanges token → Downstream Service
                                    │
                                    └── New token's subject is the GATEWAY,
                                        not Alice. Alice's identity is lost.
```

Traditional authorization after token exchange checks: "Is the **gateway service** allowed to access this resource?" — not "Is **Alice** allowed to access this resource?"

This enables **confused deputy attacks**: the gateway (acting on Alice's behalf) could access Bob's resources because the downstream service only sees the gateway's identity, not Alice's scoped authority.

## The Solution: PIC Authority Continuity Through Token Exchange

PIC solves this by treating the `act` claim in RFC 8693 as a provenance chain. The **Federation Bridge** extracts the original user (deepest `act.sub`) as `p_0`, and the `pic_ops` claim maps directly to PIC operation strings:

```
Alice authenticates with Keycloak
         │
         ▼
┌─────────────────────────────────────────────────┐
│  Keycloak (Authorization Server)                 │
│  Authenticates Alice, issues access token with:  │
│  - sub: alice                                    │
│  - pic_ops: ["read:claims:alice/*"]              │
└─────────────────────────────────────────────────┘
         │
         │ Bearer token
         ▼
┌─────────────────────────────────────────────────┐
│  Keycloak Gateway (port 3000)                    │
│  1. Receives Alice's token                       │
│  2. Performs Token Exchange (RFC 8693):           │
│     - Exchanges for pic-resource-api audience     │
│     - Exchanged token has act.sub = alice         │
│  3. Sends exchanged token to Trust Plane          │
│  4. Gets PCA_0: p_0=alice, ops=[read:claims:alice/*] │
│  5. Builds PoC, gets PCA_1 for resource-api       │
└─────────────────────────────────────────────────┘
         │
         │ X-PIC-PCA header
         ▼
┌─────────────────────────────────────────────────┐
│  Resource API (port 3001)                        │
│  1. Decodes PCA from X-PIC-PCA header            │
│  2. Checks: read:claims:alice/claim-001          │
│     ⊆ read:claims:alice/*  →  ✓ ALLOWED         │
│  3. Returns claim data                           │
└─────────────────────────────────────────────────┘
```

**The key innovation**: Even after token exchange, `p_0` is still Alice (not `service-account-pic-gateway`). Token exchange cannot launder identity.

## Architecture

```
┌──────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Keycloak │ ◄──► │   Keycloak   │ ───► │   Resource   │      │              │
│  (8180)  │      │   Gateway    │      │     API      │      │ Trust Plane  │
│          │      │   (3000)     │      │   (3001)     │      │   (8080)     │
│ OAuth AS │      │ Token Exch.  │      │ PCA Enforce  │      │ PIC Engine   │
└──────────┘      └──────────────┘      └──────────────┘      └──────────────┘
     │                   │                     │                      ▲
     │ password grant     │ issuePca()          │                      │
     │ token exchange     │ processPoc()        │                      │
     └───────────────────┼──────────────────────┼──────────────────────┘
                          └──────────────────────┘
```

### Components

1. **Keycloak** (`keycloak/`) - OAuth 2.0 Authorization Server:
   - Realm `pic-demo` with users Alice and Bob
   - Token Exchange enabled (`--features=token-exchange,admin-fine-grained-authz`)
   - `pic_ops` user attribute mapped to access token claims
   - Client `pic-gateway` authorized for token exchange

2. **Keycloak Gateway** (`keycloak-gateway/`) - Entry point that:
   - Accepts standard OAuth Bearer tokens
   - Performs OAuth Token Exchange (RFC 8693) with Keycloak
   - Issues PCA_0 via Trust Plane Federation Bridge
   - Delegates authority to resource-api via PoC

3. **Resource API** (`resource-api/`) - Protected resource server that:
   - Validates PCA from X-PIC-PCA header
   - Checks operation authorization against claim path
   - Returns claim data only if authorized
   - Final enforcement point — blocks confused deputy attacks

4. **Trust Plane** (Rust server) - The PIC authority engine that:
   - Issues PCA_0 at federation entry (JWT credential type)
   - Extracts `p_0` from the `act` claim chain (deepest subject)
   - Maps `pic_ops` claim to PIC operation strings
   - Enforces the three PIC invariants on every hop

## Running the Demo

### Prerequisites

- Rust toolchain (rustup)
- Node.js 18+
- Docker (for Keycloak)
- `curl`, `jq`

### Quick Start

```bash
./demo.sh
```

This will:
1. Build the Trust Plane, TypeScript SDK, and both services
2. Start Keycloak (Docker), Trust Plane, Gateway, and Resource API
3. Run four demo scenarios showing PIC properties

### Docker Compose (All Services)

```bash
docker-compose -f docker-compose.keycloak.yml up
```

### Manual Testing

After starting services, test manually:

```bash
# Get Alice's token from Keycloak
ALICE_TOKEN=$(curl -s -X POST http://localhost:8180/realms/pic-demo/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=pic-gateway&client_secret=pic-gateway-secret' \
  -d 'username=alice&password=alice123&scope=openid pic-operations' | jq -r '.access_token')

# Alice reads her claim (should work)
curl -s -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:3000/claims/alice/claim-001 | jq .

# Alice tries Bob's claim (should fail with 403)
curl -s -H "Authorization: Bearer $ALICE_TOKEN" \
  http://localhost:3000/claims/bob/claim-001 | jq .
```

## Demo Scenarios

| # | Scenario | Action | Result |
|---|----------|--------|--------|
| 1 | Normal flow | Alice accesses `alice/claim-001` | ✓ SUCCESS — claim returned with authority chain |
| 2 | Provenance preserved | Inspect p_0 after token exchange | ✓ p_0 = alice (not gateway service account) |
| 3 | **Confused deputy blocked** | Alice's token for `bob/claim-001` | ✗ BLOCKED — `read:claims:bob/claim-001 ⊄ read:claims:alice/*` |
| 4 | **Cross-user access blocked** | Bob's token for `alice/claim-001` | ✗ BLOCKED — `read:claims:alice/claim-001 ⊄ read:claims:bob/*` |

## The Three PIC Invariants (Through Token Exchange)

### 1. PROVENANCE: p_0 is Immutable

After token exchange, the `act` claim carries the delegation chain:
```json
{
  "sub": "service-account-pic-gateway",
  "act": { "sub": "alice-user-id" }
}
```

The Federation Bridge traverses to the deepest `act.sub` and sets `p_0 = alice`. This cannot be changed by any downstream service.

### 2. IDENTITY: Operations Can Only Shrink

Alice's Keycloak `pic_ops` attribute is `["read:claims:alice/*"]`. This becomes the ops in PCA_0. At every subsequent hop:
- `ops_{i+1} ⊆ ops_i` must hold
- The gateway cannot escalate Alice's authority
- Bob's claims are unreachable because `read:claims:bob/*` is not a subset of `read:claims:alice/*`

### 3. CONTINUITY: Cryptographic Chain

Each PCA is signed by the Trust Plane (CAT). The chain is tamper-proof:
```
PCA_0 (signed by CAT) → PoC (signed by gateway key) → PCA_1 (signed by CAT)
```

## Why Not Just Use OAuth Scopes?

| | OAuth Scopes | PIC Operations |
|--|-------------|----------------|
| **Nature** | Static permissions on a token | Cryptographically chained to origin |
| **After exchange** | New token, new subject | p_0 preserved through `act` claim |
| **Narrowing** | Client can request any scope | Monotonic: ops can only shrink |
| **Verification** | Check token at each service | Verify cryptographic chain at each hop |
| **Confused deputy** | Possible — service has broad scope | Impossible — authority traces to user |
| **Tamper resistance** | Token can be reissued with new scopes | Chain is cryptographically immutable |

**OAuth scopes** answer: "What is this **token** allowed to do?"

**PIC operations** answer: "What is this **request** allowed to do, traced back to the **original user**?"

The difference matters when services exchange tokens on behalf of users. OAuth scopes are static attributes of a token; PIC operations are dynamic, cryptographically-chained authority that cannot be escalated.

## Mock Data

The resource API has these mock claims:

| Claim ID | Owner | Type | Status | Amount |
|----------|-------|------|--------|--------|
| `alice/claim-001` | alice | auto | approved | $5,000 |
| `alice/claim-002` | alice | health | pending | $1,500 |
| `bob/claim-001` | bob | home | approved | $25,000 |
| `bob/claim-002` | bob | auto | denied | $3,000 |

Only the owner of each claim should be able to access it — enforced by PIC, not by service-level authorization.

## Keycloak Configuration

| Setting | Value |
|---------|-------|
| Realm | `pic-demo` |
| Admin credentials | `admin` / `admin` |
| Alice credentials | `alice` / `alice123` |
| Bob credentials | `bob` / `bob123` |
| Gateway client | `pic-gateway` / `pic-gateway-secret` |
| Target audience | `pic-resource-api` |
| Token Exchange | Enabled via `--features=token-exchange,admin-fine-grained-authz` |

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [WIMSE — Workload Identity in Multi System Environments](https://datatracker.ietf.org/wg/wimse/about/)
- [PIC Protocol](https://github.com/pic-protocol) — Provenance Identity Continuity theory
- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)

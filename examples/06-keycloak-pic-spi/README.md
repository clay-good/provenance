# Keycloak PIC SPI — Server-Side PIC via OAuth Token Exchange

**Server-side PIC integration**: Keycloak itself calls the Trust Plane during RFC 8693 token exchange, returning a `pic+jwt` with embedded PIC claims. No client-side PIC libraries needed.

## The Problem

OAuth Token Exchange (RFC 8693) enables service-to-service delegation, but it **launders identity**. After the exchange, the downstream token's `sub` reflects the service account — not the human who initiated the request. Traditional PIC solutions (like [Example 03](../03-keycloak-oauth-exchange/)) require each service to integrate client-side PIC libraries and separately contact the Trust Plane.

```
THE IDENTITY LAUNDERING PROBLEM:

  Alice logs in          Service A exchanges token     Service B sees...
  ┌──────────┐           ┌──────────────────────┐      ┌──────────────────┐
  │ sub=alice │  ──────►  │ RFC 8693 exchange     │ ───► │ sub=service-a    │
  │ (human)   │           │ subject_token=alice   │      │ (WHO IS ALICE?)  │
  └──────────┘           └──────────────────────┘      └──────────────────┘
                                                        Identity is LOST.
                                                        Service B only sees
                                                        the intermediary.
```

## The Solution

The **Keycloak PIC SPI** moves PIC enforcement into the Identity Provider itself:

```
THE PIC SOLUTION — IDENTITY PRESERVED:

  Alice logs in          Keycloak SPI enhances token   Service B sees...
  ┌──────────┐           ┌──────────────────────┐      ┌──────────────────┐
  │ sub=alice │  ──────►  │ RFC 8693 exchange     │ ───► │ sub=alice        │
  │ (human)   │           │ + PIC SPI intercepts  │      │ p_0=alice        │
  └──────────┘           │ + calls Trust Plane   │      │ ops=[r:alice/*]  │
                          │ + embeds PIC claims   │      │ pic_chain=[...]  │
                          └──────────────────────┘      └──────────────────┘
                                                        Identity PRESERVED.
                                                        Authority SCOPED.
                                                        Chain AUDITABLE.
```

Standard OAuth clients perform a normal RFC 8693 token exchange. The SPI:
1. Intercepts the exchange when `requested_token_type=urn:ietf:params:oauth:token-type:pic_token`
2. Extracts the origin principal (p_0) from the subject token
3. Computes the effective operations (intersection of user's authorized ops and requested scope)
4. Calls the Trust Plane to issue a PCA (Proof of Causal Authority)
5. Returns a `pic+jwt` with `pic_provenance`, `pic_ops`, and `pic_chain` claims

## System Design

### End-to-End Token Exchange Flow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    KEYCLOAK PIC SPI — COMPLETE TOKEN EXCHANGE FLOW                │
│                                                                                  │
│                                                                                  │
│   ┌─────────┐                                                    ┌────────────┐  │
│   │         │  1. POST /realms/{realm}/protocol/openid-connect   │            │  │
│   │  OAuth  │     /token                                         │   Trust    │  │
│   │  Client │                                                    │   Plane    │  │
│   │ (curl,  │     grant_type=token-exchange                      │   (Rust)   │  │
│   │  app,   │     subject_token=<alice's JWT>                    │            │  │
│   │  SDK)   │     requested_token_type=                          │  ┌──────┐  │  │
│   │         │       urn:...:pic_token                            │  │ CAT  │  │  │
│   │         │     scope=read:claims:alice/*                      │  │ Key  │  │  │
│   │         │                                                    │  └──┬───┘  │  │
│   └────┬────┘                                                    │     │      │  │
│        │          ┌──────────────────────────────────────┐       │     │      │  │
│        │          │          KEYCLOAK 26.0                │       │     │      │  │
│        │          │                                      │       │     │      │  │
│        │    1     │  ┌────────────────────────────────┐  │       │     │      │  │
│        ├─────────►│  │     PicTokenExchangeProvider    │  │       │     │      │  │
│        │          │  │                                │  │       │     │      │  │
│        │          │  │  2a. supports() → true         │  │       │     │      │  │
│        │          │  │      (pic_token type +          │  │       │     │      │  │
│        │          │  │       realm enabled +           │  │       │     │      │  │
│        │          │  │       client enabled)           │  │       │     │      │  │
│        │          │  │                                │  │       │     │      │  │
│        │          │  │  2b. exchange():               │  │       │     │      │  │
│        │          │  │      ┌────────────────────┐    │  │       │     │      │  │
│        │          │  │      │ PrincipalExtractor  │    │  │       │     │      │  │
│        │          │  │      │ Extract p_0 from    │    │  │       │     │      │  │
│        │          │  │      │ act claim chain     │    │  │       │     │      │  │
│        │          │  │      └────────────────────┘    │  │       │     │      │  │
│        │          │  │      ┌────────────────────┐    │  │  3    │     │      │  │
│        │          │  │      │ OpsResolver         │    │  │ ─────►     │      │  │
│        │          │  │      │ authorized ∩ request│    │  │ POST  │     │      │  │
│        │          │  │      │ = effective ops     │    │  │/v1/pca│     │      │  │
│        │          │  │      └────────────────────┘    │  │/issue │     │      │  │
│        │          │  │      ┌────────────────────┐    │  │       │     │      │  │
│        │          │  │      │ TrustPlaneClient    │    │  │  4    │     │      │  │
│        │          │  │      │ HTTP POST to Trust  │◄───┼──┤◄─────│     │      │  │
│        │          │  │      │ Plane, get PCA back │    │  │ PCA  │     │      │  │
│        │          │  │      └────────────────────┘    │  │signed │     │      │  │
│        │          │  │                                │  │       │     │      │  │
│        │    5     │  │  2c. Build pic+jwt:            │  │       │     │      │  │
│        │◄─────────│  │      • pic_provenance (p_0)    │  │       │     │      │  │
│        │  pic+jwt │  │      • pic_ops (effective)     │  │       │     │      │  │
│        │          │  │      • pic_chain (audit)       │  │       │     │      │  │
│        │          │  │      • Sign with realm key     │  │       │     │      │  │
│        │          │  │        (typ: "pic+jwt")        │  │       │     │      │  │
│        │          │  └────────────────────────────────┘  │       │     │      │  │
│        │          │                                      │       └────────────┘  │
│        │          └──────────────────────────────────────┘                       │
│   ┌────┴────┐                                                                    │
│   │         │                                                                    │
│   │  pic+jwt│                                                                    │
│   │  token  │   Self-contained token with provenance, scoped ops, audit chain.   │
│   │         │   No X-PIC-PCA header needed. No client-side PIC SDK needed.       │
│   └─────────┘                                                                    │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### What Happens Inside the SPI (Step-by-Step)

```
┌──────────────────────────────────────────────────────────────────┐
│                   INSIDE THE PIC SPI                              │
│                                                                  │
│  STEP 1: supports() — Should this provider handle the exchange?  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  requested_token_type == "urn:...:pic_token"  ? ──► YES   │  │
│  │  realm.pic_enabled == true                    ? ──► YES   │  │
│  │  client.pic.enabled == true                   ? ──► YES   │  │
│  │  ALL true? ──► PIC SPI handles the exchange               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  STEP 2: Validate subject token                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  session.tokens().decode(subject_token) → AccessToken      │  │
│  │  Find or create UserSession                                │  │
│  │  If invalid → 400 invalid_grant                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  STEP 3: Extract p_0 (PROVENANCE invariant)                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  PrincipalExtractor traverses the act{} claim chain:       │  │
│  │                                                            │  │
│  │  token.act.act.act...sub  ← walk to deepest act           │  │
│  │       └─ max depth: pic_max_act_depth (default 32)         │  │
│  │                                                            │  │
│  │  p_0 = "oidc:{issuer}#{sub}"  (e.g., oidc:keycloak#alice) │  │
│  │  This value is IMMUTABLE through all subsequent exchanges  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  STEP 4: Compute effective ops (IDENTITY invariant)             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  user_ops = user.getAttribute("pic_ops")                   │  │
│  │  requested_ops = parse(scope parameter)                    │  │
│  │                                                            │  │
│  │  effective_ops = intersect(user_ops, requested_ops)        │  │
│  │                                                            │  │
│  │  Example:                                                  │  │
│  │    user_ops     = [read:claims:alice/*, write:claims:*]    │  │
│  │    requested    = [read:claims:alice/*]                    │  │
│  │    effective    = [read:claims:alice/*]  ← intersection    │  │
│  │                                                            │  │
│  │  If empty intersection → 403 access_denied                 │  │
│  │  (This is how confused deputy attacks are BLOCKED)         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  STEP 5: Call Trust Plane (CONTINUITY invariant)                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Initial exchange (hop 0):                                 │  │
│  │    POST /v1/pca/issue                                      │  │
│  │    { credential, ops, executor_binding }                   │  │
│  │                                                            │  │
│  │  Multi-hop (subject is already a pic+jwt):                 │  │
│  │    POST /v1/poc/process                                    │  │
│  │    { predecessor_pca, requested_ops, executor_binding }    │  │
│  │                                                            │  │
│  │  Trust Plane verifies all invariants + signs PCA           │  │
│  │                                                            │  │
│  │  If unreachable + fail_open=false → 503 (FAIL CLOSED)     │  │
│  │  If unreachable + fail_open=true  → standard JWT (no PIC) │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  STEP 6: Build pic+jwt response                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  JOSE header: { "typ": "pic+jwt", "alg": "RS256" }        │  │
│  │                                                            │  │
│  │  Claims:                                                   │  │
│  │    sub, iss, aud, iat, exp    ← standard JWT claims        │  │
│  │    pic_provenance             ← p_0, pca_hash, cat_kid    │  │
│  │    pic_ops                    ← effective operations       │  │
│  │    pic_chain                  ← audit trail entries        │  │
│  │                                                            │  │
│  │  Sign with Keycloak's realm signing key via JWSBuilder     │  │
│  │  Return as RFC 8693 token exchange response                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Confused Deputy Attack — Blocked by Design

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                  HOW THE SPI BLOCKS CONFUSED DEPUTY ATTACKS                   │
│                                                                              │
│  SCENARIO: Alice's token is used to request Bob's data                       │
│                                                                              │
│  ┌───────────┐     ┌──────────────────────────┐     ┌──────────────────┐    │
│  │           │     │       Keycloak SPI        │     │                  │    │
│  │  Attacker │     │                          │     │  Trust Plane     │    │
│  │  or       │     │  Alice's authorized ops: │     │  (never called   │    │
│  │  Confused │     │  [read:claims:alice/*]    │     │   — blocked at   │    │
│  │  Service  │     │                          │     │   the SPI level) │    │
│  │           │     │  Requested scope:         │     │                  │    │
│  └─────┬─────┘     │  read:claims:bob/*        │     └──────────────────┘    │
│        │           │                          │                              │
│        │  POST     │  OpsResolver.intersect(): │                              │
│        │  exchange │                          │                              │
│        ├──────────►│  alice/*  ∩  bob/*  = ∅   │                              │
│        │           │                          │                              │
│        │  403      │  EMPTY INTERSECTION!      │                              │
│        │◄──────────│  → 403 access_denied      │                              │
│        │           │                          │                              │
│        │           │  "No valid PIC operations:│                              │
│        │           │   user has no authorized  │                              │
│        │           │   operations matching the │                              │
│        │           │   requested scope"        │                              │
│        │           └──────────────────────────┘                              │
│                                                                              │
│  The attack is blocked BEFORE the Trust Plane is even contacted.             │
│  Alice's pic_ops only grant access to alice/* — requesting bob/*             │
│  produces an empty intersection, and the exchange is denied.                 │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Client-Side vs Server-Side PIC

| Aspect | Client-Side (Example 03) | Server-Side (Example 06) |
|--------|--------------------------|--------------------------|
| Trust Plane caller | Each service/gateway | Keycloak SPI |
| Client code changes | Yes — PIC SDK integration | None |
| Token type | Standard JWT + X-PIC-PCA header | pic+jwt (self-contained) |
| PCA propagation | HTTP header between services | Embedded in JWT claims |
| Deployment | PIC SDK in every service | Single SPI JAR in Keycloak |

```
CLIENT-SIDE (N integrations):             SERVER-SIDE (1 integration):

┌─────────┐ ┌─────────┐ ┌─────────┐     ┌─────────┐ ┌─────────┐ ┌─────────┐
│Svc A    │ │Svc B    │ │Svc C    │     │Svc A    │ │Svc B    │ │Svc C    │
│ +PIC SDK│ │ +PIC SDK│ │ +PIC SDK│     │(no PIC) │ │(no PIC) │ │(no PIC) │
│ +config │ │ +config │ │ +config │     │         │ │         │ │         │
└────┬────┘ └────┬────┘ └────┬────┘     └────┬────┘ └────┬────┘ └────┬────┘
     │           │           │               │           │           │
     ▼           ▼           ▼               └─────┬─────┴─────┬─────┘
┌────────────────────────────────┐                 │           │
│   Trust Plane (3 connections)  │           ┌─────┴───────────┴─────┐
└────────────────────────────────┘           │   Keycloak + PIC SPI  │
                                             │   (1 integration)     │
                                             └───────────┬───────────┘
                                                         │
                                             ┌───────────┴───────────┐
                                             │ Trust Plane (1 conn.) │
                                             └───────────────────────┘
```

## Running the Demo

### Prerequisites

- **Java 17+** and **Maven** (for SPI build)
- **Rust toolchain** (for Trust Plane — `cargo`)
- **Docker** (for Keycloak + Trust Plane containers)
- **curl** and **jq**

### Quick Start

```bash
cd examples/06-keycloak-pic-spi
./demo.sh
```

The script will:
1. Build the PIC SPI JAR (Maven)
2. Build the Trust Plane (Rust)
3. Start Keycloak + Trust Plane via Docker Compose
4. Configure token exchange permissions
5. Run 7 demo scenarios

## Demo Scenarios

| # | Scenario | What It Proves |
|---|----------|----------------|
| 1 | PIC discovery (`GET /pic/well-known`) | SPI is loaded, PIC metadata discoverable |
| 2 | Alice token exchange → `pic+jwt` | PIC claims embedded in JWT, server-side |
| 3 | Inspect `pic_provenance.p_0` | **PROVENANCE**: p_0 = Alice's user ID, not service account |
| 4 | Exchange with narrowed scope | **IDENTITY**: ops narrow monotonically |
| 5 | Alice requests Bob's ops → 403 | **Confused deputy BLOCKED** |
| 6 | PIC token introspection | Introspect endpoint returns decoded PIC claims |
| 7 | Inspect `pic_chain` | **CONTINUITY**: audit trail with hop, pca_hash, cat_kid |

## PIC Token Anatomy

The SPI returns a JWT with JOSE header `typ: pic+jwt` containing these PIC-specific claims:

```json
{
  "typ": "pic+jwt",                    // JOSE header — distinguishes PIC tokens
  "alg": "RS256"
}
```

```json
{
  "sub": "alice-uuid",
  "iss": "http://localhost:8180/realms/pic-demo",
  "aud": "pic-resource-api",

  "pic_provenance": {                  // Provenance anchor
    "version": "1.0",
    "p_0": {                           // Origin principal (immutable)
      "type": "oidc",
      "value": "oidc:http://localhost:8180/realms/pic-demo#<alice-user-uuid>"
    },
    "pca_0_hash": "base64url(SHA-256(PCA_0))",
    "cat_kid": "demo-trust-plane",     // Trust Plane signing key
    "hop": 0,
    "trust_plane": "http://trust-plane:8080"
  },

  "pic_ops": [                         // Authorized operations (narrowed)
    "read:claims:alice/*",
    "write:claims:alice/*"
  ],

  "pic_chain": [                       // Cryptographic audit trail
    {
      "hop": 0,
      "executor": "pic-gateway",
      "ops": ["read:claims:alice/*", "write:claims:alice/*"],
      "pca_hash": "base64url(SHA-256(...))",
      "cat_kid": "demo-trust-plane"
    }
  ]
}
```

## SPI Module Architecture

```
keycloak-pic-spi/
├── src/main/java/com/provenance/keycloak/pic/
│   ├── PicConstants.java                  # All URNs, claim names, defaults
│   │
│   ├── exchange/                          # ━━━ CORE: Token Exchange ━━━
│   │   ├── PicTokenExchangeProvider.java  # Main exchange logic (767 lines)
│   │   ├── PicTokenExchangeProviderFactory.java  # SPI factory + lifecycle
│   │   ├── OpsResolver.java              # Operation intersection + wildcards
│   │   ├── PrincipalExtractor.java       # p_0 from act claim chains
│   │   └── PicExchangeException.java     # Typed errors → OAuth error codes
│   │
│   ├── trustplane/                        # ━━━ Trust Plane HTTP Client ━━━
│   │   ├── TrustPlaneClient.java         # Thread-safe client (issuePca, processPoc)
│   │   ├── PcaIssuanceResult.java        # PCA result DTO + SHA-256 hash
│   │   ├── TrustPlaneException.java      # MONOTONICITY_VIOLATION, REJECTED, etc.
│   │   └── TrustPlaneStatus.java         # Health check status
│   │
│   ├── resource/                          # ━━━ Public Realm Endpoints ━━━
│   │   ├── PicRealmResource.java         # /pic/well-known, /pic/introspect
│   │   ├── PicRealmResourceProvider.java
│   │   └── PicRealmResourceProviderFactory.java
│   │
│   ├── admin/                             # ━━━ Admin Endpoints ━━━
│   │   ├── PicAdminResource.java         # Key management, config updates
│   │   ├── PicAdminResourceProvider.java
│   │   └── PicAdminResourceProviderFactory.java
│   │
│   ├── audit/                             # ━━━ Event Listener ━━━
│   │   ├── PicEventListenerProvider.java  # Audit logging for PIC events
│   │   ├── PicEventListenerProviderFactory.java
│   │   └── PicAuditEvent.java            # Audit event model
│   │
│   ├── mapper/                            # ━━━ Protocol Mapper ━━━
│   │   └── PicOpsProtocolMapper.java     # Maps user attrs → pic_ops JWT claim
│   │
│   └── model/                             # ━━━ Data Models ━━━
│       ├── PicRealmConfig.java           # Realm configuration (7 attributes)
│       ├── PicProvenanceClaim.java       # pic_provenance claim structure
│       └── PicChainEntry.java            # pic_chain entry structure
│
├── src/main/resources/META-INF/services/  # 5 SPI registrations (ServiceLoader)
├── src/test/java/                         # 20 test classes
├── pom.xml                                # Keycloak 26.0, Java 17
└── Dockerfile                             # Multi-stage production build
```

## SPI Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/realms/{realm}/pic/well-known` | GET | Public | PIC discovery document |
| `/realms/{realm}/pic/introspect` | POST | Basic | PIC token introspection |
| `/realms/{realm}/protocol/openid-connect/token` | POST | Client | RFC 8693 token exchange (SPI intercepts when `requested_token_type=urn:ietf:params:oauth:token-type:pic_token`) |

## Configuration Reference

### Realm Attributes

| Attribute | Default | Description |
|-----------|---------|-------------|
| `pic_enabled` | `false` | Enable PIC for this realm |
| `pic_trust_plane_url` | — | Trust Plane server URL |
| `pic_fail_open` | `false` | Issue tokens without PIC if Trust Plane is down (NOT recommended) |
| `pic_ops_user_attribute` | `pic_ops` | User attribute containing authorized operations |
| `pic_audit_enabled` | `false` | Enable PIC audit event logging |
| `pic_max_act_depth` | `32` | Maximum `act` claim chain depth |
| `pic_token_lifetime_seconds` | `300` | PIC token TTL in seconds |

### Client Attributes

| Attribute | Description |
|-----------|-------------|
| `pic.enabled` | Enable PIC exchange for this client |
| `pic.executor.name` | Service name in chain audit entries |

### User Attributes

| Attribute | Example | Description |
|-----------|---------|-------------|
| `pic_ops` | `read:claims:alice/*,write:claims:alice/*` | Comma-separated authorized PIC operations |

## Deployment

### Docker (Production)

```dockerfile
FROM quay.io/keycloak/keycloak:26.0 as builder
COPY target/keycloak-pic-spi-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build \
    --features=token-exchange,admin-fine-grained-authz
```

### Manual Installation

1. Build: `mvn clean package -f keycloak-pic-spi/pom.xml`
2. Copy `target/keycloak-pic-spi-1.0.0-SNAPSHOT.jar` to Keycloak's `providers/` directory
3. Rebuild Keycloak: `kc.sh build --features=token-exchange,admin-fine-grained-authz`
4. Set realm attributes (`pic_enabled=true`, `pic_trust_plane_url=...`)
5. Set client attribute (`pic.enabled=true`)
6. Set user attribute (`pic_ops=read:claims:alice/*,...`)

## Three PIC Invariants Enforced by the SPI

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  1. PROVENANCE — p_0 is immutable                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  PrincipalExtractor walks the act{} chain to find p_0:    │  │
│  │  token.act.act.act...sub → deepest sub = origin human     │  │
│  │                                                            │  │
│  │  p_0 CANNOT be changed by any service in the chain.       │  │
│  │  Even after N token exchanges, p_0 is still Alice.        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  2. IDENTITY — ops can only narrow (monotonicity)               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  OpsResolver.intersect(authorized, requested):             │  │
│  │                                                            │  │
│  │  authorized = [read:claims:alice/*, write:claims:alice/*]  │  │
│  │  requested  = [read:claims:alice/*]                        │  │
│  │  effective  = [read:claims:alice/*]  ← only the overlap   │  │
│  │                                                            │  │
│  │  Supports wildcards: read:claims:alice/* matches           │  │
│  │  read:claims:alice/claim-001 (specific ⊆ wildcard)        │  │
│  │                                                            │  │
│  │  requested = [read:claims:bob/*]                           │  │
│  │  effective = []  ← EMPTY → 403 Forbidden                  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  3. CONTINUITY — cryptographic chain via Trust Plane            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  TrustPlaneClient calls /v1/pca/issue or /v1/poc/process  │  │
│  │  Trust Plane signs each PCA with its CAT key              │  │
│  │                                                            │  │
│  │  pic_chain records every hop with:                         │  │
│  │    • hop number, executor name                             │  │
│  │    • operations at that hop                                │  │
│  │    • SHA-256 hash of the signed PCA                        │  │
│  │    • CAT key ID that signed it                             │  │
│  │                                                            │  │
│  │  Any tampering invalidates the cryptographic chain.        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [WIMSE — Workload Identity in Multi-System Environments](https://datatracker.ietf.org/wg/wimse/about/)
- [PIC Protocol Specification](../../KEYCLOAK_PIC_SPI_SPEC.md)
- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)
- [Main Project README](../../README.md) — Full PIC theory and all demos

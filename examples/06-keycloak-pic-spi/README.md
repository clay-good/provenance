# Keycloak PIC SPI — Server-Side PIC via OAuth Token Exchange

**Server-side PIC integration**: Keycloak itself calls the Trust Plane during RFC 8693 token exchange, returning a `pic+jwt` with embedded PIC claims. No client-side PIC libraries needed.

## The Problem

OAuth Token Exchange (RFC 8693) enables service-to-service delegation, but it **launders identity**. After the exchange, the downstream token's `sub` reflects the service account — not the human who initiated the request. Traditional PIC solutions (like [Example 03](../03-keycloak-oauth-exchange/)) require each service to integrate client-side PIC libraries and separately contact the Trust Plane.

## The Solution

The **Keycloak PIC SPI** moves PIC enforcement into the Identity Provider itself:

```
                         ┌──────────────────────────────┐
                         │        Keycloak 26.0          │
  Client ──────────────► │                                │
  (token exchange)       │  ┌──────────┐  ┌───────────┐  │
                         │  │ PIC SPI  │──│Trust Plane │  │
                         │  └──────────┘  └───────────┘  │
  Client ◄────────────── │                                │
  (pic+jwt)              └──────────────────────────────┘
```

Standard OAuth clients perform a normal RFC 8693 token exchange. The SPI:
1. Intercepts the exchange when `requested_token_type=urn:ietf:params:oauth:token-type:pic_token`
2. Extracts the origin principal (p_0) from the subject token
3. Computes the effective operations (intersection of user's authorized ops and requested scope)
4. Calls the Trust Plane to issue a PCA (Proof of Causal Authority)
5. Returns a `pic+jwt` with `pic_provenance`, `pic_ops`, and `pic_chain` claims

## Client-Side vs Server-Side PIC

| Aspect | Client-Side (Example 03) | Server-Side (Example 06) |
|--------|--------------------------|--------------------------|
| Trust Plane caller | Each service/gateway | Keycloak SPI |
| Client code changes | Yes — PIC SDK integration | None |
| Token type | Standard JWT + X-PIC-PCA header | pic+jwt (self-contained) |
| PCA propagation | HTTP header between services | Embedded in JWT claims |
| Deployment | PIC SDK in every service | Single SPI JAR in Keycloak |

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

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌──────────────┐
│             │     │            Keycloak 26.0              │     │              │
│   Client    │────►│                                        │────►│  Trust Plane  │
│  (curl)     │     │  RFC 8693 Token Exchange               │     │              │
│             │◄────│  + PIC SPI intercepts exchange          │◄────│  Issues PCA   │
│             │     │  + Embeds pic_provenance, pic_ops,      │     │  Signs chain  │
│  pic+jwt    │     │    pic_chain in JWT                    │     │              │
└─────────────┘     └──────────────────────────────────────┘     └──────────────┘
```

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [WIMSE — Workload Identity in Multi-System Environments](https://datatracker.ietf.org/wg/wimse/about/)
- [PIC Protocol Specification](../../KEYCLOAK_PIC_SPI_SPEC.md)
- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)

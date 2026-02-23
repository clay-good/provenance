# Keycloak PIC SPI Extension Specification

## PIC Authority Continuity for OAuth Token Exchange

**Version:** 1.0.0-draft
**Date:** 2026-02-12
**Author:** Generated from PIC Trust Plane architecture
**Status:** Implementation Specification

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Design Principles](#3-design-principles)
4. [Architecture Overview](#4-architecture-overview)
5. [Module 1: PIC Token Type & Claims](#5-module-1-pic-token-type--claims)
6. [Module 2: PIC Token Exchange Provider SPI](#6-module-2-pic-token-exchange-provider-spi)
7. [Module 3: PIC Protocol Mapper SPI](#7-module-3-pic-protocol-mapper-spi)
8. [Module 4: PIC Event Listener SPI](#8-module-4-pic-event-listener-spi)
9. [Module 5: PIC Admin REST API Extension](#9-module-5-pic-admin-rest-api-extension)
10. [Module 6: Trust Plane Integration Bridge](#10-module-6-trust-plane-integration-bridge)
11. [Module 7: Packaging, Build & Deployment](#11-module-7-packaging-build--deployment)
12. [Module 8: Testing Strategy](#12-module-8-testing-strategy)
13. [Module 9: Configuration Reference](#13-module-9-configuration-reference)
14. [Security Considerations](#14-security-considerations)
15. [Migration & Compatibility](#15-migration--compatibility)
16. [File Structure](#16-file-structure)

---

## 1. Executive Summary

This specification defines a custom Keycloak SPI (Service Provider Interface) extension that embeds PIC (Provenance Identity Continuity) authority tracking directly into OAuth 2.0 Token Exchange (RFC 8693) flows. Analogous to how WIMSE extended OAuth for workload identity propagation, this extension adds **authority continuity** — cryptographic proof that traces every downstream action back to the originating human principal, with monotonically narrowing permissions at each hop.

The extension consists of six SPIs that integrate with the existing PIC Trust Plane server (`provenance-plane`) and Federation Bridge (`provenance-bridge`):

| SPI | Purpose |
|-----|---------|
| **PicTokenExchangeProvider** | Intercepts RFC 8693 token exchange to issue PIC-enhanced tokens |
| **PicProtocolMapper** | Injects `pic_provenance`, `pic_ops`, and `pic_chain` claims into tokens |
| **PicEventListener** | Audits PIC-relevant events (exchanges, violations, revocations) |
| **PicAdminResource** | Admin REST endpoints for Trust Plane configuration and key management |
| **PicRealmResource** | Realm-level REST endpoints for PCA introspection and verification |
| **TrustPlaneClient** | Java HTTP client for communicating with the Rust Trust Plane server |

---

## 2. Problem Statement

### 2.1 Token Exchange Launders Authority

Standard OAuth Token Exchange (RFC 8693) allows Service A to exchange a user's token for a new token scoped to Service B. After exchange:

```
Alice's token (sub=alice) → Gateway exchanges → New token (sub=service-account-gateway)
                                                  act: { sub: alice }
```

While the `act` claim records delegation history, **no enforcement mechanism** prevents:
- The gateway from requesting broader scopes than Alice was granted
- Downstream services from ignoring the `act` chain
- A compromised service from manufacturing arbitrary delegation chains

### 2.2 What PIC Adds

PIC adds three mathematically enforced invariants to the token exchange flow:

1. **PROVENANCE**: `p_0` (origin principal) is immutable — extracted from the deepest `act.sub` and cryptographically bound at the Trust Plane
2. **IDENTITY**: Operations monotonically narrow — `ops_{i+1} ⊆ ops_i` enforced by the Trust Plane at every exchange
3. **CONTINUITY**: Every hop is cryptographically chained via COSE_Sign1 signatures, creating a tamper-proof provenance trail

### 2.3 Relationship to WIMSE

| Aspect | WIMSE | PIC Extension |
|--------|-------|---------------|
| **Purpose** | Workload identity propagation | Authority continuity propagation |
| **Token format** | WIT + WPT (JWS-signed JWT) | PIC Token (JWT with embedded PCA reference) |
| **Key binding** | `cnf` claim (workload public key) | `pic_chain` claim (COSE_Sign1 PCA chain) |
| **Propagation** | `Workload-Identity-Token` header | `X-PIC-PCA` header + `pic_provenance` JWT claim |
| **Trust anchor** | Identity Server | Trust Plane (CAT) |
| **Exchange mechanism** | RFC 8693 with custom token type | RFC 8693 with PIC-enhanced response |

The two are complementary: WIMSE identifies *which workload* is acting; PIC proves *with what authority* and *traced to whom*.

---

## 3. Design Principles

1. **Defense in depth**: The Keycloak SPI is an additional enforcement point, not a replacement for the Trust Plane. The Trust Plane remains the authoritative validator of PIC invariants.

2. **Standards alignment**: Use RFC 8693 token exchange with a custom `requested_token_type` URN. Do not invent new grant types.

3. **Backward compatibility**: All PIC claims are additive. Standard OAuth flows work unchanged. PIC enhancement is opt-in per client.

4. **Fail-closed**: If the Trust Plane is unreachable or returns an error, token exchange MUST fail. Never issue a PIC-enhanced token without Trust Plane validation.

5. **No secrets in tokens**: PIC tokens carry references to PCA chain entries (hashes, key IDs), not the full COSE_Sign1 structures. Full chain verification requires the Trust Plane.

6. **Keycloak-native patterns**: Follow Keycloak's ProviderFactory/Provider lifecycle, use `KeycloakSession` for cross-provider access, and configure via realm attributes.

---

## 4. Architecture Overview

### 4.1 System Topology

```
                                    ┌───────────────────────────────────┐
                                    │        Keycloak Server            │
                                    │                                   │
  ┌──────────┐   password/authz     │  ┌─────────────────────────────┐  │
  │  Client   │ ──────────────────► │  │  Standard OIDC Provider     │  │
  │ (Browser/ │                     │  │  (issues access_token)      │  │
  │  Service) │                     │  └─────────────────────────────┘  │
  └──────────┘                      │              │                    │
       │                            │              ▼                    │
       │  token exchange            │  ┌─────────────────────────────┐  │
       │  (RFC 8693)                │  │  PicTokenExchangeProvider   │  │   HTTP
       └───────────────────────────►│  │  (this SPI)                │──┼──────────┐
                                    │  │                             │  │          │
                                    │  │  1. Validate subject_token  │  │          │
                                    │  │  2. Extract p_0 from act    │  │          │
                                    │  │  3. Compute pic_ops         │  │          │
                                    │  │  4. Call Trust Plane         │  │          ▼
                                    │  │  5. Embed PCA_0 reference   │  │  ┌──────────────┐
                                    │  │  6. Issue enhanced token     │  │  │ Trust Plane  │
                                    │  └─────────────────────────────┘  │  │ (Rust,       │
                                    │              │                    │  │  port 8080)  │
                                    │              ▼                    │  │              │
                                    │  ┌─────────────────────────────┐  │  │ POST /v1/    │
                                    │  │  PicProtocolMapper          │  │  │   pca/issue  │
                                    │  │  (adds claims to JWT)       │  │  │ POST /v1/    │
                                    │  └─────────────────────────────┘  │  │   poc/process│
                                    │              │                    │  └──────────────┘
                                    │              ▼                    │
                                    │  ┌─────────────────────────────┐  │
                                    │  │  PicEventListener           │  │
                                    │  │  (audit logging)            │  │
                                    │  └─────────────────────────────┘  │
                                    └───────────────────────────────────┘
```

### 4.2 Token Exchange Flow (Enhanced)

```
Step 1: Client authenticates with Keycloak (standard OIDC)
        → Receives access_token with sub=alice, pic_ops=[read:claims:alice/*]

Step 2: Gateway performs Token Exchange (RFC 8693)
        POST /realms/{realm}/protocol/openid-connect/token
        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        subject_token=<alice's access_token>
        subject_token_type=urn:ietf:params:oauth:token-type:access_token
        requested_token_type=urn:ietf:params:oauth:token-type:pic_token    ← NEW
        audience=target-service
        scope=read:claims:alice/claim-001                                   ← NARROWED

Step 3: PicTokenExchangeProvider intercepts (requested_token_type=pic_token)
        a. Validates subject_token via standard Keycloak validation
        b. Extracts p_0 = deepest act.sub (or sub if no act) = "alice"
        c. Computes pic_ops = intersection(requested_scope, token.pic_ops)
        d. Calls Trust Plane: POST /v1/pca/issue
           {
             "credential": "<subject_token>",
             "credential_type": "jwt",
             "ops": ["read:claims:alice/claim-001"],
             "executor_binding": { "service": "pic-gateway", "realm": "pic-demo" }
           }
        e. Trust Plane returns signed PCA_0 (COSE_Sign1, base64-encoded)
        f. Provider builds response JWT with PIC claims

Step 4: Response
        {
          "access_token": "<JWT with PIC claims>",
          "issued_token_type": "urn:ietf:params:oauth:token-type:pic_token",
          "token_type": "N_A",
          "expires_in": 300
        }

Step 5: Downstream services receive the PIC token and can:
        a. Verify standard JWT signature (Keycloak-signed)
        b. Extract pic_provenance.pca_0 hash to verify against Trust Plane
        c. Read pic_ops to know the narrowed authority
        d. Read pic_chain to trace the full provenance
```

### 4.3 PIC Token JWT Structure

```json
{
  "typ": "pic+jwt",
  "alg": "RS256",
  "kid": "keycloak-realm-key-id"
}
.
{
  "iss": "https://keycloak.example.com/realms/pic-demo",
  "sub": "service-account-pic-gateway",
  "aud": "target-service",
  "exp": 1700000300,
  "iat": 1700000000,
  "jti": "unique-token-id",

  "act": {
    "sub": "alice-user-id"
  },

  "pic_provenance": {
    "version": "1.0",
    "p_0": {
      "type": "oidc",
      "value": "oidc:https://keycloak.example.com/realms/pic-demo#alice-user-id"
    },
    "pca_0_hash": "base64url(SHA-256(PCA_0 COSE_Sign1 bytes))",
    "cat_kid": "trust-plane-key-id",
    "hop": 0,
    "trust_plane": "https://trust-plane.example.com"
  },

  "pic_ops": ["read:claims:alice/claim-001"],

  "pic_chain": [
    {
      "hop": 0,
      "executor": "pic-gateway",
      "ops": ["read:claims:alice/claim-001"],
      "pca_hash": "base64url(SHA-256(PCA_0))",
      "cat_kid": "trust-plane-key-id"
    }
  ]
}
```

---

## 5. Module 1: PIC Token Type & Claims

### 5.1 Custom Token Type URN

```
urn:ietf:params:oauth:token-type:pic_token
```

This URN is used as `requested_token_type` in the token exchange request and as `issued_token_type` in the response. It signals that the client wants a PIC-enhanced token with authority continuity.

### 5.2 JWT Header

| Field | Value | Description |
|-------|-------|-------------|
| `typ` | `pic+jwt` | Distinguishes PIC tokens from standard JWTs |
| `alg` | (realm default) | Standard Keycloak signing algorithm |
| `kid` | (realm key) | Standard Keycloak key ID |

### 5.3 PIC-Specific Claims

#### 5.3.1 `pic_provenance` (Object, REQUIRED)

The provenance anchor. Links this JWT to a Trust Plane PCA.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | PIC claim version, currently `"1.0"` |
| `p_0` | object | Yes | Origin principal: `{ "type": "oidc", "value": "..." }` |
| `pca_0_hash` | string | Yes | Base64url-encoded SHA-256 hash of the PCA_0 COSE_Sign1 bytes |
| `cat_kid` | string | Yes | Key ID of the Trust Plane (CAT) that signed PCA_0 |
| `hop` | integer | Yes | Current hop number (0 for initial issuance) |
| `trust_plane` | string | No | URL of the Trust Plane for verification |

#### 5.3.2 `pic_ops` (Array of Strings, REQUIRED)

The PIC operations allowed at this hop. These are the intersection of:
- The user's authorized operations (from user attributes or role mappings)
- The requested scope in the token exchange
- The predecessor's operations (for hop > 0)

Format follows the existing PIC operation syntax: `action:resource:scope` with wildcard support.

#### 5.3.3 `pic_chain` (Array of Objects, OPTIONAL)

Audit trail of the full provenance chain. Each entry records one hop.

| Field | Type | Description |
|-------|------|-------------|
| `hop` | integer | Hop number |
| `executor` | string | Service/executor name at this hop |
| `ops` | array | Operations at this hop |
| `pca_hash` | string | SHA-256 hash of the PCA at this hop |
| `cat_kid` | string | Trust Plane key that signed this PCA |

### 5.4 Constants Class

```java
// File: src/main/java/com/provenance/keycloak/pic/PicConstants.java
package com.provenance.keycloak.pic;

public final class PicConstants {

    private PicConstants() {}

    // Token type URN
    public static final String PIC_TOKEN_TYPE =
        "urn:ietf:params:oauth:token-type:pic_token";

    // JWT header type
    public static final String PIC_JWT_TYPE = "pic+jwt";

    // Claim names
    public static final String CLAIM_PIC_PROVENANCE = "pic_provenance";
    public static final String CLAIM_PIC_OPS = "pic_ops";
    public static final String CLAIM_PIC_CHAIN = "pic_chain";

    // Provenance sub-fields
    public static final String PROV_VERSION = "version";
    public static final String PROV_P0 = "p_0";
    public static final String PROV_PCA_HASH = "pca_0_hash";
    public static final String PROV_CAT_KID = "cat_kid";
    public static final String PROV_HOP = "hop";
    public static final String PROV_TRUST_PLANE = "trust_plane";

    // Current version
    public static final String PIC_VERSION = "1.0";

    // Realm attribute prefixes
    public static final String REALM_ATTR_PREFIX = "pic_";
    public static final String REALM_ATTR_TRUST_PLANE_URL = "pic_trust_plane_url";
    public static final String REALM_ATTR_TRUST_PLANE_TIMEOUT_MS = "pic_trust_plane_timeout_ms";
    public static final String REALM_ATTR_ENABLED = "pic_enabled";
    public static final String REALM_ATTR_FAIL_OPEN = "pic_fail_open";
    public static final String REALM_ATTR_OPS_ATTRIBUTE = "pic_ops_user_attribute";
    public static final String REALM_ATTR_AUDIT_ENABLED = "pic_audit_enabled";

    // Client attribute for PIC enablement
    public static final String CLIENT_ATTR_PIC_ENABLED = "pic.enabled";
    public static final String CLIENT_ATTR_PIC_EXECUTOR_NAME = "pic.executor.name";

    // User attribute for PIC operations (default)
    public static final String DEFAULT_OPS_USER_ATTRIBUTE = "pic_ops";

    // HTTP header
    public static final String PCA_HEADER = "X-PIC-PCA";

    // Default Trust Plane timeout
    public static final int DEFAULT_TRUST_PLANE_TIMEOUT_MS = 5000;
}
```

---

## 6. Module 2: PIC Token Exchange Provider SPI

This is the core SPI. It intercepts token exchange requests with `requested_token_type=urn:ietf:params:oauth:token-type:pic_token` and produces PIC-enhanced JWTs.

### 6.1 SPI Registration

**Factory registration file:**
`META-INF/services/org.keycloak.protocol.oidc.TokenExchangeProviderFactory`

**Content:**
```
com.provenance.keycloak.pic.exchange.PicTokenExchangeProviderFactory
```

### 6.2 PicTokenExchangeProviderFactory

```java
// File: src/main/java/com/provenance/keycloak/pic/exchange/PicTokenExchangeProviderFactory.java
package com.provenance.keycloak.pic.exchange;

import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;

public class PicTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    public static final String PROVIDER_ID = "pic-token-exchange";

    private TrustPlaneClient trustPlaneClient;

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new PicTokenExchangeProvider(session, trustPlaneClient);
    }

    @Override
    public void init(Config.Scope config) {
        // TrustPlaneClient is initialized lazily from realm attributes
        // because each realm may point to a different Trust Plane
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.trustPlaneClient = new TrustPlaneClient();
    }

    @Override
    public void close() {
        if (trustPlaneClient != null) {
            trustPlaneClient.close();
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        // Higher priority than default StandardTokenExchangeProvider
        // so PIC exchanges are handled by this provider
        return 100;
    }
}
```

### 6.3 PicTokenExchangeProvider

```java
// File: src/main/java/com/provenance/keycloak/pic/exchange/PicTokenExchangeProvider.java
package com.provenance.keycloak.pic.exchange;

/**
 * Core token exchange provider that intercepts RFC 8693 exchanges
 * requesting PIC tokens and enhances them with authority continuity.
 *
 * SECURITY CRITICAL: This provider enforces the bridge between OAuth
 * token exchange and PIC's three invariants. It MUST:
 * 1. Extract p_0 from the act claim chain (PROVENANCE)
 * 2. Narrow ops to intersection of requested and allowed (IDENTITY)
 * 3. Obtain a signed PCA from the Trust Plane (CONTINUITY)
 *
 * If the Trust Plane is unreachable, the exchange MUST fail (fail-closed).
 */
public class PicTokenExchangeProvider implements TokenExchangeProvider {

    // --- Implementation Requirements ---

    // supports(): Return true ONLY when:
    //   - requested_token_type == PicConstants.PIC_TOKEN_TYPE
    //   - Realm has pic_enabled=true
    //   - Requesting client has pic.enabled=true client attribute

    // exchange(): Execute the PIC-enhanced token exchange:
    //
    //   Step 1: VALIDATE SUBJECT TOKEN
    //     - Use Keycloak's built-in token validation (session.tokens())
    //     - Reject expired, revoked, or invalid tokens
    //     - Extract the original access token claims
    //
    //   Step 2: EXTRACT p_0 (Origin Principal)
    //     - If "act" claim exists: traverse to deepest act.sub (same algorithm
    //       as provenance-bridge/src/handlers/jwt.rs:deepest_act_subject_recursive)
    //     - If no "act" claim: use top-level "sub" claim
    //     - Build PrincipalIdentifier with type=oidc, value=oidc:{iss}#{sub}
    //     - CRITICAL: This becomes immutable p_0 for the entire chain
    //
    //   Step 3: COMPUTE pic_ops
    //     - Resolve user's authorized ops from:
    //       a. User attribute (realm attr pic_ops_user_attribute, default "pic_ops")
    //       b. Role-to-ops mapping (if configured)
    //       c. Scope claim in subject_token
    //     - If "scope" parameter is in the exchange request, treat as narrowing:
    //       requested_ops = parse(scope_parameter)
    //       final_ops = intersection(user_ops, requested_ops)
    //     - If no scope parameter, use full user_ops
    //     - REJECT if final_ops is empty (no valid authority to grant)
    //
    //   Step 4: CALL TRUST PLANE
    //     - Build PCA issuance request:
    //       POST {trust_plane_url}/v1/pca/issue
    //       {
    //         "credential": subject_token,
    //         "credential_type": "jwt",
    //         "ops": final_ops,
    //         "executor_binding": {
    //           "service": client.pic.executor.name,
    //           "realm": realm.name,
    //           "client_id": client.clientId
    //         }
    //       }
    //     - Handle errors:
    //       - Trust Plane unreachable → 503 Service Unavailable
    //       - Trust Plane rejects → 403 Forbidden with error details
    //       - Trust Plane timeout → 504 Gateway Timeout
    //     - NEVER fall back to issuing a non-PIC token on failure
    //
    //   Step 5: BUILD PIC TOKEN
    //     - Create JWT with standard claims (iss, sub, aud, exp, iat, jti)
    //     - Add "act" claim preserving the delegation chain from subject_token
    //     - Add pic_provenance claim with PCA_0 reference
    //     - Add pic_ops claim with final_ops
    //     - Add pic_chain claim with hop 0 entry
    //     - Set typ header to "pic+jwt"
    //     - Sign with realm's active signing key
    //
    //   Step 6: RETURN RESPONSE
    //     - issued_token_type = PicConstants.PIC_TOKEN_TYPE
    //     - token_type = "N_A" (not a bearer token in the traditional sense)
    //     - expires_in = min(trust_plane_pca_exp, realm_token_lifespan)
    //     - No refresh_token (PIC tokens are short-lived, re-exchange required)
}
```

### 6.4 Principal Extraction Algorithm

This mirrors the Rust implementation in `provenance-bridge/src/handlers/jwt.rs`:

```java
// File: src/main/java/com/provenance/keycloak/pic/exchange/PrincipalExtractor.java
package com.provenance.keycloak.pic.exchange;

/**
 * Extracts the origin principal (p_0) from JWT claims.
 *
 * For token exchange tokens with an "act" claim, traverses to the deepest
 * act.sub to find the original human user. This matches the algorithm in
 * provenance-bridge/src/handlers/jwt.rs:deepest_act_subject_recursive.
 *
 * Example:
 *   { "sub": "service-B", "act": { "sub": "service-A", "act": { "sub": "alice" } } }
 *   → returns "alice"
 */
public class PrincipalExtractor {

    /**
     * Extract the origin principal from token claims.
     *
     * @param claims The JWT claims map
     * @param issuer The token issuer
     * @return PrincipalInfo containing the extracted p_0
     * @throws PicExchangeException if no principal can be extracted
     */
    // extractPrincipal(Map<String, Object> claims, String issuer): PrincipalInfo

    /**
     * Recursively traverse the act claim chain to find the deepest subject.
     * Returns the most deeply nested act.sub value, which represents the
     * original user who initiated the delegation chain.
     *
     * SECURITY: This method MUST be recursive-safe (bounded depth).
     * Maximum depth is 32 levels (configurable). Beyond that, reject
     * the token as malformed to prevent stack overflow attacks.
     *
     * @param actClaim The "act" claim object
     * @param depth Current recursion depth
     * @return The deepest subject string, or null if not found
     */
    // deepestActSubject(Map<String, Object> actClaim, int depth): String

    // MAX_ACT_DEPTH = 32  (prevent stack overflow from malicious tokens)
}
```

### 6.5 Operations Resolution

```java
// File: src/main/java/com/provenance/keycloak/pic/exchange/OpsResolver.java
package com.provenance.keycloak.pic.exchange;

/**
 * Resolves PIC operations for a user within a realm.
 *
 * Operations come from multiple sources with this priority:
 * 1. User attribute (pic_ops) - explicit PIC operations
 * 2. Role-to-ops mapping - realm roles mapped to PIC operations
 * 3. OAuth scopes - standard scopes as fallback
 *
 * The resolver computes the intersection of the user's authorized ops
 * and the requested ops (from the exchange "scope" parameter), enforcing
 * the IDENTITY invariant (ops can only shrink).
 */
public class OpsResolver {

    /**
     * Resolve the effective PIC operations for a token exchange.
     *
     * @param session The Keycloak session
     * @param user The authenticated user
     * @param requestedScope The scope parameter from the exchange request (may be null)
     * @return List of PIC operation strings
     * @throws PicExchangeException if no valid operations can be resolved
     */
    // resolveOps(KeycloakSession session, UserModel user, String requestedScope): List<String>

    /**
     * Load user's authorized PIC operations from user attributes.
     * The attribute name is configurable via realm attribute pic_ops_user_attribute.
     *
     * The attribute value can be:
     * - A JSON array: ["read:claims:alice/*", "write:claims:alice/*"]
     * - A space-delimited string: "read:claims:alice/* write:claims:alice/*"
     * - Multiple attribute values (Keycloak supports multi-valued attributes)
     */
    // loadUserOps(UserModel user, String attributeName): List<String>

    /**
     * Compute the intersection of authorized and requested operations.
     * Uses wildcard-aware matching consistent with provenance-core's
     * operation containment check (Pca::contains_op).
     *
     * A requested op "read:claims:alice/001" is covered by authorized op
     * "read:claims:alice/*" because the wildcard prefix matches.
     *
     * @param authorizedOps The user's full authorized operations
     * @param requestedOps The operations requested in this exchange
     * @return The intersection (ops that are both authorized and requested)
     */
    // intersectOps(List<String> authorizedOps, List<String> requestedOps): List<String>
}
```

---

## 7. Module 3: PIC Protocol Mapper SPI

The protocol mapper adds PIC claims to tokens that pass through standard Keycloak token flows (not just exchanges). This enables PIC-aware clients to receive `pic_ops` claims on regular access tokens.

### 7.1 SPI Registration

**Factory registration file:**
`META-INF/services/org.keycloak.protocol.ProtocolMapper`

**Content:**
```
com.provenance.keycloak.pic.mapper.PicOpsProtocolMapper
```

### 7.2 PicOpsProtocolMapper

```java
// File: src/main/java/com/provenance/keycloak/pic/mapper/PicOpsProtocolMapper.java
package com.provenance.keycloak.pic.mapper;

/**
 * Protocol mapper that adds the pic_ops claim to access tokens.
 *
 * This mapper reads the user's PIC operations from user attributes
 * and adds them as a JSON array claim on the access token. This
 * enables the Federation Bridge (provenance-bridge JWT handler)
 * to extract PIC operations without requiring a full token exchange.
 *
 * Configurable properties (set in Keycloak admin console):
 * - User attribute name (default: "pic_ops")
 * - Token claim name (default: "pic_ops")
 * - Add to access token (default: true)
 * - Add to ID token (default: false)
 * - Add to userinfo (default: false)
 */
public class PicOpsProtocolMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "pic-ops-mapper";

    // --- Config properties shown in admin console ---
    // PROPERTY_USER_ATTRIBUTE: The user attribute to read (default: "pic_ops")
    // PROPERTY_CLAIM_NAME: The JWT claim name (default: "pic_ops")
    // PROPERTY_ADD_ARRAY: Whether to add as JSON array (default: true)

    // getDisplayType(): return "PIC Operations"
    // getHelpText(): return "Maps user's PIC operation attributes to a JWT claim"
    // getDisplayCategory(): return TOKEN_MAPPER_CATEGORY

    // setClaim(IDToken token, ProtocolMapperModel model, UserSessionModel session, ...):
    //   1. Read user attribute from model config (PROPERTY_USER_ATTRIBUTE)
    //   2. Get attribute values from user model
    //   3. Parse as PIC operations (JSON array or space-delimited)
    //   4. Set claim on token as JSON array
}
```

---

## 8. Module 4: PIC Event Listener SPI

### 8.1 SPI Registration

**Factory registration file:**
`META-INF/services/org.keycloak.events.EventListenerProviderFactory`

**Content:**
```
com.provenance.keycloak.pic.audit.PicEventListenerProviderFactory
```

### 8.2 PicEventListenerProvider

```java
// File: src/main/java/com/provenance/keycloak/pic/audit/PicEventListenerProvider.java
package com.provenance.keycloak.pic.audit;

/**
 * Event listener that captures PIC-relevant security events for auditing.
 *
 * Events captured:
 * - TOKEN_EXCHANGE with PIC token type → log PCA issuance details
 * - TOKEN_EXCHANGE_ERROR → log failed PIC exchanges with reason
 * - LOGIN / LOGOUT → correlate with PIC sessions
 * - CUSTOM_REQUIRED_ACTION → PIC-specific admin actions
 *
 * Output: Structured JSON logs compatible with the Trust Plane's audit format.
 * Each log entry includes:
 * - Timestamp (ISO 8601)
 * - Event type (pic_exchange, pic_exchange_denied, pic_monotonicity_violation)
 * - Realm ID
 * - User ID and username
 * - Client ID
 * - p_0 (origin principal)
 * - pic_ops (requested operations)
 * - PCA hash (if issued)
 * - Error details (if failed)
 *
 * The listener MUST NOT block the token exchange flow. Audit failures
 * are logged as warnings but do not prevent token issuance.
 */
public class PicEventListenerProvider implements EventListenerProvider {

    // onEvent(Event event):
    //   Switch on event.getType():
    //     TOKEN_EXCHANGE:
    //       - Check if details contain PIC token type
    //       - Log: pic_exchange event with p_0, ops, pca_hash
    //     TOKEN_EXCHANGE_ERROR:
    //       - Check if details indicate PIC exchange attempt
    //       - Log: pic_exchange_denied with error reason
    //     LOGIN:
    //       - Log: pic_session_start (correlate future exchanges)
    //     LOGOUT:
    //       - Log: pic_session_end

    // onEvent(AdminEvent event, boolean includeRepresentation):
    //   Capture admin changes to PIC configuration:
    //     - Realm attribute changes with pic_ prefix
    //     - Client attribute changes with pic. prefix
    //     - User attribute changes for pic_ops
}
```

### 8.3 Structured Audit Log Format

```json
{
  "timestamp": "2026-02-12T14:30:00.000Z",
  "event": "pic_exchange",
  "realm": "pic-demo",
  "user_id": "alice-user-id",
  "username": "alice",
  "client_id": "pic-gateway",
  "p_0": "oidc:https://keycloak.example.com/realms/pic-demo#alice-user-id",
  "pic_ops": ["read:claims:alice/claim-001"],
  "pca_0_hash": "base64url(SHA-256(...))",
  "trust_plane": "https://trust-plane.example.com",
  "cat_kid": "trust-plane-key-1",
  "hop": 0,
  "exchange_duration_ms": 45,
  "outcome": "success"
}
```

---

## 9. Module 5: PIC Admin REST API Extension

### 9.1 Admin-Level Endpoints

**SPI Registration File:**
`META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory`

These endpoints allow administrators to configure PIC settings for a realm.

```java
// File: src/main/java/com/provenance/keycloak/pic/admin/PicAdminResourceProvider.java
package com.provenance.keycloak.pic.admin;

/**
 * Admin REST API endpoints for PIC configuration.
 *
 * Base path: /admin/realms/{realm}/pic
 *
 * Endpoints:
 *
 * GET  /admin/realms/{realm}/pic/config
 *   Returns the current PIC configuration for the realm.
 *   Response: PicRealmConfig JSON object
 *
 * PUT  /admin/realms/{realm}/pic/config
 *   Updates the PIC configuration for the realm.
 *   Request body: PicRealmConfig JSON object
 *   Requires: realm-admin role
 *
 * GET  /admin/realms/{realm}/pic/status
 *   Returns the Trust Plane connectivity status.
 *   Performs a health check against the configured Trust Plane URL.
 *   Response: { "trust_plane_url": "...", "status": "healthy|unhealthy", "latency_ms": 12 }
 *
 * GET  /admin/realms/{realm}/pic/keys
 *   Lists executor keys registered with the Trust Plane for this realm.
 *   Response: Array of { kid, service_name, registered_at, expires_at }
 *
 * POST /admin/realms/{realm}/pic/keys
 *   Registers a new executor key with the Trust Plane.
 *   Request body: { "kid": "...", "public_key": "base64...", "service_name": "..." }
 *   Requires: realm-admin role
 *
 * DELETE /admin/realms/{realm}/pic/keys/{kid}
 *   Revokes an executor key.
 *   Requires: realm-admin role
 *
 * POST /admin/realms/{realm}/pic/verify
 *   Verifies a PCA chain. Accepts a PCA (base64 COSE_Sign1) and verifies it
 *   against the Trust Plane.
 *   Request body: { "pca": "base64..." }
 *   Response: { "valid": true, "p_0": "...", "ops": [...], "hop": 0 }
 */
```

### 9.2 Realm-Level Endpoints (Public)

```java
// File: src/main/java/com/provenance/keycloak/pic/resource/PicRealmResourceProvider.java
package com.provenance.keycloak.pic.resource;

/**
 * Public realm-level REST endpoints for PIC introspection.
 *
 * Base path: /realms/{realm}/pic
 *
 * Endpoints:
 *
 * GET  /realms/{realm}/pic/well-known
 *   PIC discovery document (similar to .well-known/openid-configuration).
 *   Response:
 *   {
 *     "pic_version": "1.0",
 *     "trust_plane_url": "https://trust-plane.example.com",
 *     "pic_token_type": "urn:ietf:params:oauth:token-type:pic_token",
 *     "supported_ops_formats": ["pic-colon-separated"],
 *     "cat_kid": "trust-plane-key-id",
 *     "pca_verification_endpoint": "/realms/{realm}/pic/verify",
 *     "token_exchange_endpoint": "/realms/{realm}/protocol/openid-connect/token"
 *   }
 *
 * POST /realms/{realm}/pic/introspect
 *   Introspects a PIC token and returns the decoded PIC claims.
 *   Requires: valid client authentication (client_id + client_secret)
 *   Request body (form-encoded): token=<pic_token>
 *   Response:
 *   {
 *     "active": true,
 *     "p_0": { "type": "oidc", "value": "..." },
 *     "pic_ops": ["read:claims:alice/*"],
 *     "hop": 0,
 *     "pca_valid": true,
 *     "chain_length": 1
 *   }
 */
```

### 9.3 PicRealmConfig Data Model

```java
// File: src/main/java/com/provenance/keycloak/pic/model/PicRealmConfig.java
package com.provenance.keycloak.pic.model;

/**
 * Configuration model for PIC settings within a realm.
 * Stored as realm attributes with the pic_ prefix.
 */
public class PicRealmConfig {
    /** Whether PIC is enabled for this realm */
    private boolean enabled;                    // pic_enabled

    /** URL of the Trust Plane server */
    private String trustPlaneUrl;               // pic_trust_plane_url

    /** HTTP timeout for Trust Plane calls (ms) */
    private int trustPlaneTimeoutMs;            // pic_trust_plane_timeout_ms (default: 5000)

    /** Whether to fail open if Trust Plane is unreachable (default: false)
     *  SECURITY WARNING: Setting this to true defeats PIC's security guarantees.
     *  Only use for debugging/development. */
    private boolean failOpen;                   // pic_fail_open

    /** User attribute name for PIC operations (default: "pic_ops") */
    private String opsUserAttribute;            // pic_ops_user_attribute

    /** Whether to enable PIC audit logging (default: true) */
    private boolean auditEnabled;               // pic_audit_enabled

    /** Maximum act claim chain depth (default: 32) */
    private int maxActDepth;                    // pic_max_act_depth

    /** PIC token lifetime in seconds (default: 300) */
    private int tokenLifetimeSeconds;           // pic_token_lifetime_seconds

    // Getters, setters, toRealmAttributes(), fromRealmAttributes() methods
}
```

---

## 10. Module 6: Trust Plane Integration Bridge

### 10.1 TrustPlaneClient

```java
// File: src/main/java/com/provenance/keycloak/pic/trustplane/TrustPlaneClient.java
package com.provenance.keycloak.pic.trustplane;

import java.net.http.HttpClient;

/**
 * HTTP client for communicating with the PIC Trust Plane (Rust server).
 *
 * This client implements the Trust Plane API as defined in
 * provenance-plane/src/api/handlers/*.rs.
 *
 * Thread-safety: This client is thread-safe and designed to be shared
 * across multiple Keycloak request threads. It uses java.net.http.HttpClient
 * which is thread-safe by design.
 *
 * Connection management: Uses a shared HttpClient with connection pooling.
 * Timeouts are configurable per-realm via PicRealmConfig.
 *
 * Error handling: All Trust Plane communication errors result in
 * TrustPlaneException, which the PicTokenExchangeProvider translates
 * to appropriate OAuth error responses.
 */
public class TrustPlaneClient implements AutoCloseable {

    private final HttpClient httpClient;

    /**
     * Issue a PCA_0 at federation entry.
     *
     * Calls: POST {trustPlaneUrl}/v1/pca/issue
     *
     * Request body (matches provenance-plane IssuePcaRequest):
     * {
     *   "credential": "<JWT access token>",
     *   "credential_type": "jwt",
     *   "ops": ["read:claims:alice/*"],
     *   "executor_binding": {
     *     "service": "pic-gateway",
     *     "realm": "pic-demo",
     *     "client_id": "pic-gateway"
     *   }
     * }
     *
     * Response body (matches provenance-plane IssuePcaResponse):
     * {
     *   "pca": "<base64 COSE_Sign1 bytes>",
     *   "p_0": "oidc:issuer#subject",
     *   "ops": ["read:claims:alice/*"],
     *   "cat_kid": "trust-plane-key-id",
     *   "exp": "2026-02-12T15:00:00Z"
     * }
     *
     * @param config Realm PIC configuration
     * @param credential The subject token (JWT string)
     * @param ops Requested PIC operations
     * @param executorBinding Executor metadata
     * @return PcaIssuanceResult containing the PCA and metadata
     * @throws TrustPlaneException if the Trust Plane rejects or is unreachable
     */
    // issuePca(PicRealmConfig config, String credential, List<String> ops,
    //          Map<String, String> executorBinding): PcaIssuanceResult

    /**
     * Process a PoC (Proof of Continuity) to get a successor PCA.
     *
     * Calls: POST {trustPlaneUrl}/v1/poc/process
     *
     * Used when a PIC-enhanced token is exchanged again (multi-hop).
     * The predecessor PCA from the incoming token is included in the PoC.
     *
     * @param config Realm PIC configuration
     * @param predecessorPca Base64-encoded predecessor PCA (COSE_Sign1)
     * @param requestedOps Operations requested for the successor
     * @param executorBinding Executor metadata for this hop
     * @return PcaIssuanceResult for the successor PCA
     * @throws TrustPlaneException on failure
     */
    // processPoc(PicRealmConfig config, String predecessorPca, List<String> requestedOps,
    //            Map<String, String> executorBinding): PcaIssuanceResult

    /**
     * Register an executor key with the Trust Plane.
     *
     * Calls: POST {trustPlaneUrl}/v1/keys/executor
     *
     * @param config Realm PIC configuration
     * @param kid Key identifier
     * @param publicKey Base64-encoded Ed25519 public key (32 bytes)
     * @param serviceName Human-readable service name
     * @throws TrustPlaneException on failure
     */
    // registerExecutorKey(PicRealmConfig config, String kid, String publicKey,
    //                     String serviceName): void

    /**
     * Health check against the Trust Plane.
     *
     * Calls: GET {trustPlaneUrl}/health
     *
     * @param trustPlaneUrl The Trust Plane URL
     * @param timeoutMs Timeout in milliseconds
     * @return TrustPlaneStatus with health and latency info
     */
    // healthCheck(String trustPlaneUrl, int timeoutMs): TrustPlaneStatus

    @Override
    public void close() {
        // HttpClient doesn't require explicit close in Java 11+
        // but we include this for future connection pool cleanup
    }
}
```

### 10.2 Data Transfer Objects

```java
// File: src/main/java/com/provenance/keycloak/pic/trustplane/PcaIssuanceResult.java
package com.provenance.keycloak.pic.trustplane;

/**
 * Result of a PCA issuance from the Trust Plane.
 */
public class PcaIssuanceResult {
    /** Base64-encoded COSE_Sign1 PCA bytes */
    private String pca;

    /** Origin principal (p_0) as extracted by Trust Plane */
    private String p0;

    /** Effective operations granted */
    private List<String> ops;

    /** Trust Plane key ID (CAT kid) that signed the PCA */
    private String catKid;

    /** PCA expiration (ISO 8601) */
    private String exp;

    /** SHA-256 hash of the PCA bytes (for JWT claim embedding) */
    public String pcaHash() {
        // return Base64url(SHA-256(Base64decode(pca)))
    }
}
```

```java
// File: src/main/java/com/provenance/keycloak/pic/trustplane/TrustPlaneException.java
package com.provenance.keycloak.pic.trustplane;

/**
 * Exception thrown when Trust Plane communication fails.
 */
public class TrustPlaneException extends Exception {

    public enum FailureType {
        /** Trust Plane is unreachable (network error) */
        UNREACHABLE,
        /** Trust Plane returned an error response */
        REJECTED,
        /** Trust Plane call timed out */
        TIMEOUT,
        /** Response was malformed */
        INVALID_RESPONSE,
        /** Monotonicity violation detected by Trust Plane */
        MONOTONICITY_VIOLATION
    }

    private final FailureType failureType;
    private final int httpStatus;        // 0 if no HTTP response
    private final String trustPlaneError; // Error body from Trust Plane
}
```

---

## 11. Module 7: Packaging, Build & Deployment

### 11.1 Maven Project Structure

```xml
<!-- File: pom.xml -->
<project>
    <groupId>com.provenance.keycloak</groupId>
    <artifactId>keycloak-pic-spi</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>jar</packaging>

    <properties>
        <java.version>17</java.version>
        <keycloak.version>26.0.0</keycloak.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- Keycloak SPIs (all provided scope - Keycloak supplies at runtime) -->
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-core</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi-private</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-services</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>

        <!-- JSON processing (provided by Keycloak) -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <scope>provided</scope>
        </dependency>

        <!-- Jakarta REST (provided by Keycloak/Quarkus) -->
        <dependency>
            <groupId>jakarta.ws.rs</groupId>
            <artifactId>jakarta.ws.rs-api</artifactId>
            <scope>provided</scope>
        </dependency>

        <!-- Logging (provided by Keycloak) -->
        <dependency>
            <groupId>org.jboss.logging</groupId>
            <artifactId>jboss-logging</artifactId>
            <scope>provided</scope>
        </dependency>

        <!-- ===== TEST DEPENDENCIES ===== -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.assertj</groupId>
            <artifactId>assertj-core</artifactId>
            <version>3.25.3</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>com.github.dasniko</groupId>
            <artifactId>testcontainers-keycloak</artifactId>
            <version>3.3.0</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>1.19.5</version>
            <scope>test</scope>
        </dependency>
        <!-- WireMock for Trust Plane stubbing in tests -->
        <dependency>
            <groupId>org.wiremock</groupId>
            <artifactId>wiremock-standalone</artifactId>
            <version>3.4.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.12.1</version>
                <configuration>
                    <source>17</source>
                    <target>17</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.2.5</version>
            </plugin>
            <!-- Shade plugin not needed - Keycloak deps are provided -->
        </plugins>
    </build>
</project>
```

### 11.2 Service Registration Files

```
src/main/resources/META-INF/services/
├── org.keycloak.protocol.oidc.TokenExchangeProviderFactory
│   └── com.provenance.keycloak.pic.exchange.PicTokenExchangeProviderFactory
├── org.keycloak.protocol.ProtocolMapper
│   └── com.provenance.keycloak.pic.mapper.PicOpsProtocolMapper
├── org.keycloak.events.EventListenerProviderFactory
│   └── com.provenance.keycloak.pic.audit.PicEventListenerProviderFactory
└── org.keycloak.services.resource.RealmResourceProviderFactory
    ├── com.provenance.keycloak.pic.admin.PicAdminResourceProviderFactory
    └── com.provenance.keycloak.pic.resource.PicRealmResourceProviderFactory
```

### 11.3 Deployment

```bash
# Build the JAR
mvn clean package -DskipTests

# Copy to Keycloak providers directory
cp target/keycloak-pic-spi-1.0.0-SNAPSHOT.jar $KEYCLOAK_HOME/providers/

# Rebuild Keycloak (required for Quarkus-based Keycloak 26+)
$KEYCLOAK_HOME/bin/kc.sh build

# Restart Keycloak
$KEYCLOAK_HOME/bin/kc.sh start-dev  # or start for production
```

### 11.4 Docker Deployment

```dockerfile
# File: keycloak-pic-spi/Dockerfile
FROM quay.io/keycloak/keycloak:26.0 AS builder

COPY target/keycloak-pic-spi-*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build \
    --features=token-exchange

FROM quay.io/keycloak/keycloak:26.0

COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

---

## 12. Module 8: Testing Strategy

### 12.1 Unit Tests

Test individual components without Keycloak or Trust Plane:

```java
// File: src/test/java/com/provenance/keycloak/pic/exchange/PrincipalExtractorTest.java

/**
 * Tests for PrincipalExtractor — the p_0 extraction algorithm.
 * These mirror the tests in provenance-bridge/src/handlers/jwt.rs.
 */
class PrincipalExtractorTest {

    // test_single_level_act_claim:
    //   act: { sub: "alice" } → p_0 = "alice"

    // test_two_level_act_chain:
    //   act: { sub: "gateway", act: { sub: "alice" } } → p_0 = "alice"

    // test_three_level_act_chain:
    //   act: { sub: "service-B", act: { sub: "service-A", act: { sub: "alice" } } }
    //   → p_0 = "alice"

    // test_no_act_claim_uses_sub:
    //   sub: "alice" (no act) → p_0 = "alice"

    // test_max_depth_exceeded_rejects:
    //   33 levels of nesting → PicExchangeException

    // test_act_without_sub_returns_null:
    //   act: { "other": "value" } → null (parent handles fallback)

    // test_empty_act_returns_null:
    //   act: {} → null
}
```

```java
// File: src/test/java/com/provenance/keycloak/pic/exchange/OpsResolverTest.java

/**
 * Tests for OpsResolver — operation intersection logic.
 * These mirror the wildcard tests in provenance-plane/src/core/validation.rs.
 */
class OpsResolverTest {

    // test_exact_match_intersection:
    //   authorized: [read:claims:123], requested: [read:claims:123]
    //   → [read:claims:123]

    // test_wildcard_covers_specific:
    //   authorized: [read:claims:*], requested: [read:claims:123]
    //   → [read:claims:123]

    // test_universal_wildcard:
    //   authorized: [*], requested: [read:anything, write:anything]
    //   → [read:anything, write:anything]

    // test_no_overlap_returns_empty:
    //   authorized: [read:claims:alice/*], requested: [read:claims:bob/*]
    //   → []

    // test_partial_overlap:
    //   authorized: [read:claims:*], requested: [read:claims:123, write:claims:123]
    //   → [read:claims:123] (write not authorized)

    // test_nested_wildcard_matching:
    //   authorized: [read:claims:alice/*], requested: [read:claims:alice/doc1]
    //   → [read:claims:alice/doc1]

    // test_empty_authorized_returns_empty:
    //   authorized: [], requested: [read:anything]
    //   → []

    // test_empty_requested_returns_empty:
    //   authorized: [read:*], requested: []
    //   → []
}
```

### 12.2 Integration Tests with Testcontainers

```java
// File: src/test/java/com/provenance/keycloak/pic/integration/PicTokenExchangeIT.java

/**
 * Full integration test using Testcontainers.
 *
 * Spins up:
 * 1. Keycloak container with PIC SPI loaded
 * 2. WireMock as a Trust Plane stub
 *
 * Tests the complete token exchange flow end-to-end.
 */
@Testcontainers
class PicTokenExchangeIT {

    // @Container: KeycloakContainer with .withProviderClassesFrom("target/classes")
    //             and .withRealmImportFile("/test-realm-pic.json")
    // @Container: WireMockContainer as Trust Plane stub

    // test_pic_token_exchange_happy_path:
    //   1. Authenticate as Alice → get access_token
    //   2. Token exchange with requested_token_type=pic_token
    //   3. Verify response has pic_provenance, pic_ops, pic_chain claims
    //   4. Verify p_0 is "alice" (not service account)
    //   5. Verify WireMock received correct PCA issuance request

    // test_pic_exchange_narrowed_scope:
    //   1. Alice has pic_ops=["read:claims:alice/*", "write:claims:alice/*"]
    //   2. Exchange with scope=read:claims:alice/claim-001
    //   3. Verify pic_ops in response is ["read:claims:alice/claim-001"]

    // test_pic_exchange_unauthorized_scope_rejected:
    //   1. Alice has pic_ops=["read:claims:alice/*"]
    //   2. Exchange with scope=read:claims:bob/*
    //   3. Verify 403 Forbidden (no valid intersection)

    // test_pic_exchange_trust_plane_down_fails_closed:
    //   1. Stop WireMock (Trust Plane stub)
    //   2. Attempt token exchange
    //   3. Verify 503 Service Unavailable (not fallback to standard token)

    // test_pic_exchange_preserves_act_chain:
    //   1. Create a token with existing act chain (simulating multi-hop)
    //   2. Token exchange
    //   3. Verify act chain in response includes both original and new actor

    // test_standard_exchange_unaffected:
    //   1. Token exchange WITHOUT requested_token_type=pic_token
    //   2. Verify standard Keycloak exchange works normally
    //   3. Verify no PIC claims in response

    // test_pic_disabled_realm_rejects:
    //   1. Realm has pic_enabled=false
    //   2. Attempt PIC token exchange
    //   3. Verify appropriate error (unsupported token type)

    // test_pic_disabled_client_rejects:
    //   1. Realm has pic_enabled=true but client has pic.enabled=false
    //   2. Attempt PIC token exchange
    //   3. Verify appropriate error
}
```

### 12.3 Trust Plane Stub Configuration

```java
// File: src/test/java/com/provenance/keycloak/pic/integration/TrustPlaneStub.java

/**
 * WireMock stubs that simulate the Trust Plane API.
 *
 * These stubs return pre-computed PCA responses matching the format
 * from provenance-plane/src/api/handlers/issue.rs.
 */
class TrustPlaneStub {

    // stubIssuePca():
    //   POST /v1/pca/issue → 200 with mock PCA response
    //   Validates request body has required fields

    // stubIssuePcaRejected():
    //   POST /v1/pca/issue → 403 with error body

    // stubHealthCheck():
    //   GET /health → 200 { "status": "healthy" }

    // stubProcessPoc():
    //   POST /v1/poc/process → 200 with mock successor PCA

    // stubMonotonicityViolation():
    //   POST /v1/poc/process → 403 with monotonicity error
}
```

### 12.4 Test Realm Configuration

```json
// File: src/test/resources/test-realm-pic.json
{
  "realm": "pic-test",
  "enabled": true,
  "attributes": {
    "pic_enabled": "true",
    "pic_trust_plane_url": "http://wiremock:8080",
    "pic_trust_plane_timeout_ms": "3000",
    "pic_fail_open": "false",
    "pic_ops_user_attribute": "pic_ops",
    "pic_audit_enabled": "true",
    "pic_token_lifetime_seconds": "300"
  },
  "clients": [
    {
      "clientId": "pic-gateway",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "pic-gateway-secret",
      "serviceAccountsEnabled": true,
      "attributes": {
        "pic.enabled": "true",
        "pic.executor.name": "pic-gateway"
      },
      "defaultClientScopes": ["openid", "pic-operations"]
    },
    {
      "clientId": "pic-resource-api",
      "enabled": true,
      "bearerOnly": true,
      "attributes": {
        "pic.enabled": "true",
        "pic.executor.name": "pic-resource-api"
      }
    },
    {
      "clientId": "non-pic-client",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "non-pic-secret",
      "attributes": {}
    }
  ],
  "users": [
    {
      "username": "alice",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "alice123" }],
      "attributes": {
        "pic_ops": ["read:claims:alice/*", "write:claims:alice/*"]
      }
    },
    {
      "username": "bob",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "bob123" }],
      "attributes": {
        "pic_ops": ["read:claims:bob/*"]
      }
    }
  ],
  "clientScopes": [
    {
      "name": "pic-operations",
      "protocol": "openid-connect",
      "protocolMappers": [
        {
          "name": "pic-ops-mapper",
          "protocol": "openid-connect",
          "protocolMapper": "pic-ops-mapper",
          "config": {
            "user.attribute": "pic_ops",
            "claim.name": "pic_ops",
            "access.token.claim": "true",
            "id.token.claim": "false"
          }
        }
      ]
    }
  ]
}
```

---

## 13. Module 9: Configuration Reference

### 13.1 Realm Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `pic_enabled` | boolean | `false` | Enable PIC token exchange for this realm |
| `pic_trust_plane_url` | string | (required) | URL of the Trust Plane server (e.g., `http://trust-plane:8080`) |
| `pic_trust_plane_timeout_ms` | integer | `5000` | HTTP timeout for Trust Plane calls |
| `pic_fail_open` | boolean | `false` | If true, issue standard tokens when Trust Plane is down. **SECURITY WARNING**: Defeats PIC guarantees. |
| `pic_ops_user_attribute` | string | `pic_ops` | User attribute name containing PIC operations |
| `pic_audit_enabled` | boolean | `true` | Enable structured PIC audit logging |
| `pic_max_act_depth` | integer | `32` | Maximum `act` claim chain depth before rejection |
| `pic_token_lifetime_seconds` | integer | `300` | Lifetime of PIC-enhanced tokens |

### 13.2 Client Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `pic.enabled` | boolean | `false` | Enable PIC token exchange for this client |
| `pic.executor.name` | string | (client ID) | Service name used in executor binding |

### 13.3 User Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `pic_ops` | string[] | PIC operations authorized for this user. JSON array or space-delimited. Example: `["read:claims:alice/*", "write:claims:alice/*"]` |

### 13.4 Keycloak Server Configuration

```bash
# Enable token exchange feature (required for RFC 8693)
bin/kc.sh build --features=token-exchange

# Or via environment variable
KC_FEATURES=token-exchange
```

---

## 14. Security Considerations

### 14.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Token replay** | Short PIC token lifetime (5 min default). PCA_0 bound to specific ops and executor. |
| **Privilege escalation via scope widening** | OpsResolver computes intersection; Trust Plane enforces monotonicity. Two independent checks. |
| **Trust Plane impersonation** | Trust Plane URL configured as realm attribute by admin. TLS required in production. PCA signatures verified via Trust Plane's published public key. |
| **act claim forgery** | Only Keycloak can issue tokens with `act` claims (signed by realm key). The SPI validates the subject_token signature before extracting `act`. |
| **Denial of service via deep act chains** | `pic_max_act_depth` limits recursion depth (default: 32). |
| **Configuration tampering** | Realm/client attributes require admin role to modify. PicEventListener audits all configuration changes. |
| **Fail-open misconfiguration** | `pic_fail_open` defaults to `false`. When `true`, a warning is logged on every request and the audit log records it. |
| **PCA hash collision** | SHA-256 provides 128-bit collision resistance. Sufficient for the lifetime of PIC tokens. |
| **Information leakage** | `pic_chain` claim is optional and should only be enabled when audit trails are needed in downstream tokens. PCA hashes are one-way (cannot reconstruct PCA from hash). |

### 14.2 Security Invariants

The SPI MUST enforce these invariants. Violation of any is a security bug:

1. **Never issue a PIC token without Trust Plane confirmation.** If `pic_fail_open` is false (default), Trust Plane unreachability MUST result in exchange failure.

2. **Never widen operations.** The final `pic_ops` MUST be a subset of both the user's authorized operations AND the predecessor's operations (for multi-hop).

3. **Never modify p_0.** The origin principal extracted from the deepest `act.sub` MUST be passed unchanged to the Trust Plane and embedded unchanged in the PIC token.

4. **Never issue PIC tokens for non-PIC clients.** Both the realm (`pic_enabled`) and client (`pic.enabled`) must opt in.

5. **Never skip subject_token validation.** The subject token MUST be validated (signature, expiry, issuer) via Keycloak's built-in mechanisms before any PIC processing begins.

### 14.3 Secure Defaults

- `pic_enabled`: false (opt-in per realm)
- `pic_fail_open`: false (fail-closed)
- `pic_max_act_depth`: 32 (bounded recursion)
- `pic_token_lifetime_seconds`: 300 (short-lived)
- `pic_audit_enabled`: true (audit everything)

---

## 15. Migration & Compatibility

### 15.1 Compatibility with Existing PIC Components

| Component | Compatibility Notes |
|-----------|-------------------|
| **provenance-core** | PIC token claims map directly to PCA fields. `pic_provenance.p_0` → `Pca.p_0`. `pic_ops` → `Pca.ops`. |
| **provenance-plane** | SPI calls the same REST API (`/v1/pca/issue`, `/v1/poc/process`) that existing TypeScript/Rust clients use. No changes needed. |
| **provenance-bridge JWT handler** | PIC tokens issued by this SPI are valid JWTs that the bridge can validate when `token_exchange_aware=true`. The `act` claim and `pic_ops` claim are preserved. |
| **TypeScript SDK** | Can consume PIC tokens via the existing `TrustPlaneClient`. The `pic_provenance.pca_0_hash` allows verification against cached PCAs. |
| **Example 03 (Keycloak OAuth Exchange)** | This SPI replaces the gateway-side token exchange logic with server-side enforcement. The example can be updated to use `requested_token_type=pic_token` instead of manual Trust Plane calls. |

### 15.2 Keycloak Version Requirements

- **Minimum**: Keycloak 26.0 (Quarkus-based, TokenExchangeProvider SPI available)
- **Required Features**: `token-exchange` (must be enabled at build time)
- **Java**: 17+ (Keycloak 26 requirement)

### 15.3 Upgrade Path

For existing deployments using Example 03 (gateway-side PIC):

1. **Phase 1**: Deploy SPI alongside existing gateway. Both paths work simultaneously.
2. **Phase 2**: Migrate clients to use `requested_token_type=pic_token` in exchange requests.
3. **Phase 3**: Remove gateway-side Trust Plane calls (the SPI handles it).

---

## 16. File Structure

```
keycloak-pic-spi/
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/com/provenance/keycloak/pic/
│   │   │   ├── PicConstants.java                           # Constants and URNs
│   │   │   ├── exchange/
│   │   │   │   ├── PicTokenExchangeProvider.java           # Core SPI: token exchange
│   │   │   │   ├── PicTokenExchangeProviderFactory.java    # Factory for above
│   │   │   │   ├── PrincipalExtractor.java                 # p_0 extraction from act chain
│   │   │   │   ├── OpsResolver.java                        # PIC operations resolution
│   │   │   │   └── PicExchangeException.java               # Exchange-specific exceptions
│   │   │   ├── mapper/
│   │   │   │   ├── PicOpsProtocolMapper.java               # Protocol mapper: pic_ops claim
│   │   │   │   └── PicOpsProtocolMapperFactory.java        # Factory for above
│   │   │   ├── audit/
│   │   │   │   ├── PicEventListenerProvider.java           # Event listener: audit logging
│   │   │   │   ├── PicEventListenerProviderFactory.java    # Factory for above
│   │   │   │   └── PicAuditEvent.java                      # Structured audit event model
│   │   │   ├── admin/
│   │   │   │   ├── PicAdminResourceProvider.java           # Admin REST: config & keys
│   │   │   │   ├── PicAdminResourceProviderFactory.java    # Factory for above
│   │   │   │   └── PicAdminResource.java                   # JAX-RS resource class
│   │   │   ├── resource/
│   │   │   │   ├── PicRealmResourceProvider.java           # Public REST: discovery & introspect
│   │   │   │   ├── PicRealmResourceProviderFactory.java    # Factory for above
│   │   │   │   └── PicRealmResource.java                   # JAX-RS resource class
│   │   │   ├── model/
│   │   │   │   ├── PicRealmConfig.java                     # Realm configuration model
│   │   │   │   ├── PicProvenanceClaim.java                 # pic_provenance claim model
│   │   │   │   └── PicChainEntry.java                      # pic_chain entry model
│   │   │   └── trustplane/
│   │   │       ├── TrustPlaneClient.java                   # HTTP client for Trust Plane
│   │   │       ├── PcaIssuanceResult.java                  # PCA issuance response DTO
│   │   │       ├── TrustPlaneException.java                # Trust Plane error types
│   │   │       └── TrustPlaneStatus.java                   # Health check result DTO
│   │   └── resources/
│   │       └── META-INF/services/
│   │           ├── org.keycloak.protocol.oidc.TokenExchangeProviderFactory
│   │           ├── org.keycloak.protocol.ProtocolMapper
│   │           ├── org.keycloak.events.EventListenerProviderFactory
│   │           └── org.keycloak.services.resource.RealmResourceProviderFactory
│   └── test/
│       ├── java/com/provenance/keycloak/pic/
│       │   ├── exchange/
│       │   │   ├── PrincipalExtractorTest.java             # Unit: p_0 extraction
│       │   │   └── OpsResolverTest.java                    # Unit: ops intersection
│       │   ├── trustplane/
│       │   │   └── TrustPlaneClientTest.java               # Unit: HTTP client
│       │   └── integration/
│       │       ├── PicTokenExchangeIT.java                 # Integration: full flow
│       │       └── TrustPlaneStub.java                     # WireMock Trust Plane stubs
│       └── resources/
│           └── test-realm-pic.json                         # Test realm configuration
└── Dockerfile                                              # Docker build for Keycloak + SPI
```

---

## Build Order for Implementation

Each module can be built incrementally. The recommended order ensures each piece is testable before the next depends on it:

### Phase 1: Foundation (no Keycloak dependency) ✅ COMPLETED
1. ✅ **PicConstants.java** — All constants and URNs
2. ✅ **PrincipalExtractor.java** + **PicExchangeException.java** + tests (17 tests) — p_0 extraction algorithm (pure Java, no Keycloak APIs)
3. ✅ **OpsResolver.java** + tests (31 tests) — Operations intersection logic (pure Java, no Keycloak APIs)
4. ✅ **Model classes** + tests (25 tests) — PicRealmConfig, PicProvenanceClaim, PicChainEntry (POJOs)

> **Phase 1 verified:** 73 tests passing, BUILD SUCCESS. All implementations mirror the Rust codebase algorithms exactly.

### Phase 2: Trust Plane Client ✅ COMPLETED
5. ✅ **TrustPlaneClient.java** + tests (24 WireMock tests) — HTTP client for `/v1/pca/issue`, `/v1/poc/process`, `/v1/keys/executor`, `/health`
6. ✅ **PcaIssuanceResult.java** + tests (10 tests) — DTO for Trust Plane responses with `pcaHash()` (Base64url SHA-256)
7. ✅ **TrustPlaneException.java** + tests (10 tests) — Error types with 5 failure classifications and transient detection

> **Phase 2 verified:** 117 tests passing (73 Phase 1 + 44 Phase 2), BUILD SUCCESS. All DTOs match Rust API request/response structures exactly.

### Phase 3: Core SPI ✅ COMPLETED
8. ✅ **PicTokenExchangeProvider.java** + tests (22 tests) — Core exchange logic implementing `TokenExchangeProvider` SPI: `supports()` with 3-gate check (token type + realm + client), `exchange()` with 6-step flow (validate → extract p_0 → compute ops → call Trust Plane → build PIC JWT → return response), Trust Plane error handling with fail-closed semantics
9. ✅ **PicTokenExchangeProviderFactory.java** + tests (7 tests) — Factory with lifecycle management, shared `TrustPlaneClient`, order=100 priority, provider ID `"pic-token-exchange"`

> **Phase 3 verified:** 146 tests passing (117 Phase 1+2 + 29 Phase 3), BUILD SUCCESS. Provider integrates all Phase 1 (PrincipalExtractor, OpsResolver, model classes) and Phase 2 (TrustPlaneClient, PcaIssuanceResult) components.

### Phase 4: Supporting SPIs ✅ COMPLETED
10. ✅ **PicOpsProtocolMapper.java** + tests (7 tests) — Protocol mapper extending `AbstractOIDCProtocolMapper` that reads user's PIC operations from configurable user attribute and adds them as a JSON array claim on access/ID tokens. Provider ID `"pic-ops-mapper"`, configurable user attribute and claim name via admin console.
11. ✅ **PicEventListenerProvider.java** + **PicEventListenerProviderFactory.java** + tests (22 tests) — Event listener capturing PIC-relevant security events: `TOKEN_EXCHANGE` with PIC token type (log PCA issuance), `TOKEN_EXCHANGE_ERROR` (log denials with monotonicity violation detection), `LOGIN`/`LOGOUT` (session correlation), admin events (PIC config changes). Structured JSON audit logs via dedicated `PIC_AUDIT` logger. Non-blocking: audit failures never propagate to exchange flow. Factory provider ID `"pic-audit"`.
12. ✅ **PicAuditEvent.java** + tests (11 tests) — Structured audit model with 6 event types (`pic_exchange`, `pic_exchange_denied`, `pic_monotonicity_violation`, `pic_session_start`, `pic_session_end`, `pic_config_change`), 3 outcomes (`success`, `denied`, `error`), builder-style setters, and `toMap()` for JSON serialization matching Trust Plane audit format. Also created META-INF/services registration files for all Phase 4 SPIs plus Phase 3's TokenExchangeProviderFactory.

> **Phase 4 verified:** 200 tests passing (146 Phase 1-3 + 54 Phase 4), BUILD SUCCESS. All three supporting SPIs integrate with existing Phase 1 components (OpsResolver for ops parsing, PicConstants for attribute names/token types).

### Phase 5: REST APIs ✅ COMPLETED
13. ✅ **PicAdminResource.java** + **PicAdminResourceProvider.java** + **PicAdminResourceProviderFactory.java** + tests (24 tests) — Admin REST endpoints at `/admin/realms/{realm}/pic/...` using `AdminRealmResourceProvider` SPI. Endpoints: `GET /config` (read PIC realm config), `PUT /config` (update config, requires realm-admin, validates pic_ prefix), `GET /status` (Trust Plane health check with latency), `GET /keys` (list executor keys from Trust Plane), `POST /keys` (register executor key, requires realm-admin). Also added `listExecutorKeys()` method to TrustPlaneClient for `GET /v1/keys/executor` API. All endpoints enforce admin authorization via `AdminPermissionEvaluator`.
14. ✅ **PicRealmResource.java** + **PicRealmResourceProvider.java** + **PicRealmResourceProviderFactory.java** + tests (18 tests) — Public realm-level REST endpoints at `/realms/{realm}/pic/...` using `RealmResourceProvider` SPI. Endpoints: `GET /well-known` (PIC discovery document with version, token type, Trust Plane URL, endpoint URLs), `POST /introspect` (PIC token introspection — decodes token, validates expiry, extracts pic_provenance/pic_ops/pic_chain claims, returns active/inactive with full PIC metadata). Also created META-INF/services registration files for both REST SPIs.

> **Phase 5 verified:** 245 tests passing (200 Phase 1-4 + 45 Phase 5), BUILD SUCCESS. REST APIs integrate with TrustPlaneClient (health check, key listing/registration) and PicRealmConfig (config read/write via realm attributes). All 5 META-INF/services files now registered for TokenExchangeProviderFactory, ProtocolMapper, EventListenerProviderFactory, AdminRealmResourceProviderFactory, RealmResourceProviderFactory.

### Phase 6: Integration ✅ COMPLETED
15. ✅ **Service registration files** — All 5 META-INF/services files verified: TokenExchangeProviderFactory, ProtocolMapper, EventListenerProviderFactory, AdminRealmResourceProviderFactory, RealmResourceProviderFactory.
16. ✅ **test-realm-pic.json** — Full test realm configuration with realm "pic-test", pic_enabled=true, Trust Plane URL pointing to WireMock. 3 clients (pic-gateway with pic.enabled=true, pic-resource-api bearer-only, non-pic-client without PIC). 3 users: alice (read+write claims ops), bob (read-only claims ops), no-ops-user (no ops attribute).
17. ✅ **TrustPlaneStub.java** — WireMock stubs for all Trust Plane endpoints: `stubIssuePca()`, `stubIssuePcaWithOps()`, `stubIssuePcaRejected()`, `stubMonotonicityViolation()`, `stubProcessPoc()`, `stubHealthCheck()`, `stubListExecutorKeys()`, `stubRegisterExecutorKey()`, `configureAllStubs()`, `reset()`. Constants: MOCK_PCA_BASE64, MOCK_P0, MOCK_CAT_KID.
18. ✅ **PicTokenExchangeIT.java** — Full integration test suite (25 tests) using Testcontainers + WireMock. Tests: happy path (PIC token with pic_provenance/pic_ops/pic_chain), narrowed scope (intersection produces subset), unauthorized scope rejection (403), Trust Plane down fails closed, standard exchange unaffected (no PIC claims), PIC-disabled client rejection, Trust Plane rejection propagation, monotonicity violation rejection. Uses Testcontainers host bridge (`host.testcontainers.internal`) for WireMock connectivity. Keycloak container configured with `withProviderClassesFrom("target/classes")`, `withRealmImportFile()`, `withFeaturesEnabled("token-exchange")`. Realm Trust Plane URL updated dynamically via admin client after startup.
19. ✅ **Dockerfile** — Multi-stage Docker build: builder stage copies SPI JAR and runs `kc.sh build --features=token-exchange`, production stage copies the built Keycloak. Base image: `quay.io/keycloak/keycloak:26.0`.
20. ✅ **pom.xml** — Finalized with maven-failsafe-plugin (3.2.5) for integration tests (*IT.java) with integration-test and verify goals. All dependencies and plugins complete. (keycloak-admin-client removed — replaced with raw HTTP calls in IT tests.)

> **Phase 6 verified:** 245 unit tests passing, BUILD SUCCESS. Integration test (PicTokenExchangeIT) compiles and is excluded from `mvn test` (surefire). IT tests run via `mvn verify` (failsafe). Dockerfile and pom.xml finalized. All 20 implementation steps across 6 phases are complete.

### Post-Completion Audit Remediation ✅ COMPLETED

Comprehensive spec-vs-implementation audit performed and the following gaps were identified and fixed:

1. ✅ **catKid field added to PcaIssuanceResult** — Spec (Section 10.2) defines `private String catKid` but implementation was missing it. Added `catKid` field, constructor parameter, and `getCatKid()` getter. Updated `TrustPlaneClient.IssuePcaResponse` and `ProcessPocResponse` DTOs to deserialize `@JsonProperty("cat_kid")`. Updated `PicTokenExchangeProvider.extractCatKid()` to use the actual Trust Plane key ID instead of truncated PCA hash workaround.

2. ✅ **clientScopes section added to test-realm-pic.json** — Spec (Section 12.4) defines a `pic-operations` client scope with `pic-ops-mapper` protocol mapper. Added the `clientScopes` section and updated `pic-gateway` client's `defaultClientScopes` to include `pic-operations`.

3. ✅ **DELETE /keys/{kid} admin endpoint implemented** — Spec (Section 9.1) defines `DELETE /admin/realms/{realm}/pic/keys/{kid}` for key revocation. Added `revokeKey()` endpoint to `PicAdminResource` and `revokeExecutorKey()` method to `TrustPlaneClient`. 6 unit tests added.

4. ✅ **POST /verify admin endpoint implemented** — Spec (Section 9.1) defines `POST /admin/realms/{realm}/pic/verify` for PCA chain verification. Added `verifyPca()` endpoint to `PicAdminResource` with Base64 validation and SHA-256 hash computation. 5 unit tests added.

5. ✅ **Missing integration tests added** — Spec (Section 12.2) defines `test_pic_exchange_preserves_act_chain` and `test_pic_disabled_realm_rejects`. Both implemented in `PicTokenExchangeIT.java`. Also added `stubRevokeExecutorKey()` to `TrustPlaneStub`.

> **Audit remediation verified:** 258 unit tests passing (13 new tests added), BUILD SUCCESS. All spec gaps closed.

### Post-Completion Audit Remediation (Round 2) ✅ COMPLETED

Deep audit of remaining spec-vs-implementation gaps performed. Two issues identified and fixed:

1. ✅ **Well-known endpoint missing `cat_kid` and `pca_verification_endpoint`** — Spec (Section 9.2, lines 842-843) defines `cat_kid` and `pca_verification_endpoint` as fields in the PIC discovery document. `PicRealmResource.getWellKnown()` was missing both. Added `cat_kid` (null at discovery level — actual value is per-PCA in `pic_provenance`) and `pca_verification_endpoint` URL. Added `wellKnown_includesCatKid` test to `PicRealmResourceTest` and `pca_verification_endpoint` assertion to existing `wellKnown_includesEndpoints` test.

2. ✅ **Protocol mapper config key misaligned** — Spec (Section 12.4, line 1519) defines config key as `"user.attribute"` matching standard Keycloak convention, but `PicOpsProtocolMapper.CONFIG_USER_ATTRIBUTE` was set to `"pic.ops.user.attribute"`. Changed to `"user.attribute"` to match spec. Updated `test-realm-pic.json` accordingly.

> **Audit remediation verified:** 259 unit tests passing (1 new test added), BUILD SUCCESS. All spec gaps closed.

### Post-Completion Audit Remediation (Round 3) ✅ COMPLETED

Comprehensive deep audit across all modules. Seven gaps identified and fixed:

1. ✅ **Introspect endpoint missing client authentication (CRITICAL)** — Spec (Section 9.2, line 849) requires "valid client authentication (client_id + client_secret)" for the introspect endpoint. `PicRealmResource.introspect()` was accepting requests without any authentication. Added HTTP Basic authentication via `authenticateClient()` method that validates client_id and client_secret against the realm's client registry. Returns 401 with `WWW-Authenticate: Basic` header on failure. 3 auth tests added.

2. ✅ **`registerExecutorKey` missing `serviceName` parameter** — Spec (Section 10.1, lines 999-1003) defines `registerExecutorKey(config, kid, publicKey, serviceName)` with 4 params. Implementation had only 3. Added `serviceName` parameter and `@JsonProperty("service_name")` to `RegisterExecutorRequest` DTO.

3. ✅ **Admin POST /keys missing `service_name` field** — Spec (Section 9.1, line 806) defines request body with `service_name` field. `PicAdminResource.registerKey()` now extracts and forwards `service_name` to `TrustPlaneClient.registerExecutorKey()`.

4. ✅ **`OpsResolver.intersectOps` empty-requested behavior** — Spec (Section 12.1, lines 1343-1345) defines `test_empty_requested_returns_empty: authorized: [read:*], requested: [] → []`. Implementation was returning all authorized ops for empty requested. Fixed: null = no narrowing (returns all), empty list = empty result. Test updated.

5. ✅ **CUSTOM_REQUIRED_ACTION event not handled** — Spec (Section 8.2, line 703) lists `CUSTOM_REQUIRED_ACTION` as a captured event type. Added `handleCustomRequiredAction()` to `PicEventListenerProvider` with PIC-relevance filtering. 2 tests added.

6. ✅ **Username missing from audit events** — Spec (Section 8.3, line 755) includes `username` in the structured audit log format. All event handlers now call `.username(extractUsername(event))` to populate the username from event details.

7. ✅ **IT test `p_0` ClassCastException** — `PicTokenExchangeIT.test_pic_token_exchange_happy_path()` cast `p_0` to `String` but `PicProvenanceClaim.toClaimMap()` produces a `Map<String, String>` with `type` and `value` keys. Fixed to cast to `Map` and assert on `value` key.

> **Audit remediation verified:** 264 unit tests passing (5 new tests added), BUILD SUCCESS. All spec gaps closed.

### Post-Completion Audit Remediation (Round 4) ✅ COMPLETED

Deep audit focusing on Appendix B error mapping, fail-open semantics, multi-hop successor flow, and file structure. Eight gaps identified; seven fixed, one confirmed as non-issue:

1. ✅ **REJECTED error mapped to `access_denied` (CRITICAL)** — Spec (Appendix B, line 1895) defines Trust Plane rejection as `access_denied`, but `mapToOAuthError()` in `PicTokenExchangeProvider` returned `invalid_grant` for `REJECTED`. Fixed to return `access_denied`.

2. ✅ **`fail_open=true` behavior incomplete (CRITICAL)** — Spec (Section 14.2, line 1593) states fail-open mode should issue a standard token without PIC claims when Trust Plane is unreachable. `handleTrustPlaneError()` was always throwing `CorsErrorResponseException`. Fixed: transient errors (UNREACHABLE, TIMEOUT) now return `null` when `fail_open=true`, and the caller invokes `buildFailOpenTokenResponse()` to issue a standard Bearer token without `pic_provenance`/`pic_chain` claims. Hard failures (REJECTED, MONOTONICITY_VIOLATION, INVALID_RESPONSE) still throw regardless of fail-open setting. 4 tests added.

3. ✅ **`processPoc()` parameter mismatch (CRITICAL)** — Spec (Section 10.2, lines 973-989) defines `processPoc(config, predecessorPca, requestedOps, executorBinding)` with 4 params. Implementation had only 2 params `(config, poc)`. Updated to 4-param signature. Updated `ProcessPocRequest` DTO with `@JsonProperty("predecessor_pca")`, `@JsonProperty("requested_ops")`, and `@JsonProperty("executor_binding")` fields. All tests updated.

4. ✅ **Multi-hop successor flow not implemented (CRITICAL)** — Spec (Appendix A.2, lines 1842-1882) defines the successor PIC exchange where a subject token that already contains `pic_provenance` should route to `/v1/poc/process` instead of `/v1/pca/issue`. Added `extractPredecessorPca()` method that inspects the subject token's `pic_provenance` claim for `pca_0_hash`. The `exchange()` method now branches: initial tokens go to `issuePca()`, successor tokens go to `processPoc()`. Updated `buildPicTokenResponse()` to preserve predecessor chain entries in `pic_chain`. 4 tests added.

5. ⏭️ **PicOpsProtocolMapperFactory not a separate file** — Spec (Section 16, line 1672) lists a separate `PicOpsProtocolMapperFactory.java`. However, in Keycloak's ProtocolMapper SPI, `AbstractOIDCProtocolMapper` already serves as both mapper and factory (implementing `ProtocolMapperModel` and providing `create()` via inheritance). Creating a separate factory class would be architecturally incorrect. **Skipped — not a real gap.**

6. ✅ **`TrustPlaneStatus` not extracted to separate file** — Spec (Section 16, line 1679) lists `TrustPlaneStatus.java` as a standalone file. Was an inner class of `TrustPlaneClient`. Extracted to `com.provenance.keycloak.pic.trustplane.TrustPlaneStatus` as its own top-level class. Updated all references in `PicAdminResource`, `PicAdminResourceTest`, and `TrustPlaneClientTest`.

7. ✅ **`pic_max_act_depth` missing from test realm** — Spec (Section 12.4) defines `pic_max_act_depth` as a realm attribute. `test-realm-pic.json` was missing it. Added `"pic_max_act_depth": "32"` to realm attributes.

8. ⏭️ **META-INF/services file count** — Spec (Section 16, line 1694) lists 4 SPI service files but implementation has 5 (includes `AdminRealmResourceProviderFactory`). The extra file is required for the admin REST endpoints to register with Keycloak. **Not a gap — spec list was illustrative, not exhaustive.**

> **Audit remediation verified:** 272 unit tests passing (8 new tests added), BUILD SUCCESS. All spec gaps closed.

### Post-Completion Audit Remediation (Round 5) ✅ COMPLETED

Deep audit across all 10 spec areas: constants, config model, claim models, executor binding, principal extraction depth, introspect response, admin event handling, Trust Plane request format, and META-INF services. One gap identified and fixed:

1. ✅ **PrincipalExtractor ignoring realm-configurable `pic_max_act_depth`** — Spec (Section 13.1, line 1545) defines `pic_max_act_depth` as a configurable realm attribute (default: 32). `PicRealmConfig.fromRealmAttributes()` correctly parses this value, but `PicTokenExchangeProvider` created `PrincipalExtractor` in its constructor with the hardcoded default, ignoring the realm setting. Fixed: `PrincipalExtractor` is now created inside `exchange()` using `realmConfig.getMaxActDepth()`, ensuring the per-realm configured depth is respected. Removed the `principalExtractor` field from the provider.

**Verified compliant (no gaps):**
- PicConstants.java — all constants match spec Section 5.4
- PicRealmConfig.java — all 8 fields, parsing, and defaults match spec Section 9.3/13.1
- PicProvenanceClaim.java — all fields including optional `trust_plane` match spec Section 5.3.1
- PicChainEntry.java — all 5 fields including `cat_kid` match spec Section 5.3.3
- PicTokenExchangeProvider executor binding — includes `service`, `realm`, `client_id` per spec Section 6.3
- PicRealmResource introspect — returns all 6 required fields per spec Section 9.2
- PicEventListenerProvider admin events — captures `pic_` prefix realm, `pic.` prefix client, and user attribute changes per spec Section 8.2
- TrustPlaneClient issuePca — request body matches spec Section 10.1 exactly
- META-INF/services — correct separation of AdminRealmResourceProviderFactory and RealmResourceProviderFactory

> **Audit remediation verified:** 272 unit tests passing, BUILD SUCCESS. All spec gaps closed.

### Integration Test Hardening ✅ COMPLETED

Full end-to-end integration tests executed against a real Keycloak 26.0 container with the PIC SPI loaded and WireMock as a Trust Plane stub. Three issues discovered and fixed:

1. ✅ **Keycloak admin client Jackson deserialization failure** — Keycloak 26.0.x added a new `bruteForceStrategy` field to `RealmRepresentation` that the 26.0.0 admin client library doesn't know. Replaced all typed admin client (`Keycloak`/`KeycloakBuilder`/`RealmRepresentation`) usage in IT tests with raw HTTP calls using `java.net.http.HttpClient` and a lenient Jackson `ObjectMapper` (FAIL_ON_UNKNOWN_PROPERTIES=false) for realm GET/PUT operations.

2. ✅ **Subject token `sub` claim not populated by `session.tokens().decode()`** — Keycloak 26's internal token decoder does not always populate `AccessToken.getSubject()`. Added fallback in `extractClaimsMap()`: if `sub` is missing from both typed fields and `otherClaims`, uses the authenticated user's Keycloak ID from the resolved `UserModel`. Also added defensive checks in `otherClaims` for `sub` and `iss` fields.

3. ✅ **p_0 assertion too strict** — Integration test asserted that `p_0.value` contains "alice" (username), but Keycloak's `sub` claim is the user's UUID. Updated assertion to verify the format `oidc:{issuer}/realms/{realm}#{user-uuid}` without requiring the username.

> **Integration test verified:** 272 unit tests + 10 integration tests passing, BUILD SUCCESS. Full end-to-end PIC token exchange flow confirmed working against live Keycloak 26.0 container.

### Deep Integration Testing ✅ COMPLETED

Comprehensive deep E2E testing against live Keycloak 26.0 container. 15 new integration tests added (25 total), 1 critical bug discovered and fixed, 1 unused dependency removed.

**Bug found and fixed:**

1. ✅ **JWT JOSE header `typ` hardcoded to "JWT" instead of "pic+jwt" (CRITICAL)** — Spec (Section 4.3, line 196) requires PIC tokens to have JOSE header `typ: "pic+jwt"`. `PicTokenExchangeProvider` was calling `session.tokens().encode(picToken)`, which hardcodes the JOSE header `typ` to `"JWT"` regardless of what `AccessToken.type()` is set to (Keycloak's `DefaultTokenManager.type()` only returns "JWT" or "at+jwt" for ACCESS category tokens). Fixed by using `JWSBuilder` directly with `SignatureProvider.signer()` to produce the signed JWT with the custom `typ` header. This ensures PIC tokens are distinguishable from standard JWTs by any downstream service inspecting the JOSE header.

**New integration tests (15 added to PicTokenExchangeIT.java):**

- `test_pic_token_jwt_header_type` — Verifies JOSE header `typ=pic+jwt`, `alg`, and `kid` are present
- `test_pic_provenance_all_fields` — Deep verification of all 6 `pic_provenance` sub-fields: `version=1.0`, `p_0.{type,value}`, `pca_0_hash`, `cat_kid`, `hop=0`, `trust_plane`
- `test_pic_chain_entry_all_fields` — Deep verification of all 5 `pic_chain` entry fields: `hop`, `executor=pic-gateway`, `ops[]`, `pca_hash`, `cat_kid`
- `test_pic_token_lifetime` — Verifies `expires_in=300` in response and `exp - iat = 300` in JWT
- `test_pic_exchange_no_refresh_token` — Verifies no `refresh_token` in response (PIC tokens are short-lived)
- `test_pic_exchange_bob_read_only_ops` — Bob gets `["read:claims:bob/*"]` only (no write ops)
- `test_pic_exchange_bob_cannot_access_alice_claims` — Bob requesting Alice's claims rejected
- `test_pic_exchange_no_ops_user_rejected` — User with no `pic_ops` attribute gets 403
- `test_trust_plane_receives_correct_request_body` — WireMock body verification: `credential`, `credential_type=jwt`, `ops[]`, `executor_binding.{service,realm,client_id}`
- `test_pic_well_known_endpoint` — E2E test of `/realms/pic-test/pic/well-known`: version, enabled, token type, trust_plane_url, endpoints
- `test_pic_introspect_endpoint` — E2E PIC token introspection: active=true, token_type, provenance, ops, chain, pca_valid
- `test_pic_introspect_rejects_without_auth` — Introspect without Basic auth returns 401
- `test_pic_introspect_non_pic_token_inactive` — Standard access token introspected as inactive
- `test_pic_exchange_fail_open_mode` — E2E fail-open: Trust Plane down + `pic_fail_open=true` → standard Bearer token without PIC claims
- `test_pic_exchange_alice_and_bob_different_ops` — Concurrent users: Alice (read+write) and Bob (read-only) get different ops and different p_0 values

**Dependency cleanup:**

- ✅ Removed unused `keycloak-admin-client` dependency from `pom.xml` (replaced with raw HTTP in IT tests during Integration Test Hardening)

> **Deep integration test verified:** 272 unit tests + 25 integration tests passing, BUILD SUCCESS. All PIC invariants (PROVENANCE, IDENTITY, CONTINUITY) confirmed end-to-end against live Keycloak 26.0 container.

### E2E Docker Demo Testing ✅ COMPLETED

Full end-to-end testing of the `examples/06-keycloak-pic-spi` demo against live Keycloak 26.0 + Trust Plane Docker containers. All 7 demo scenarios verified. 6 bugs found and fixed during initial testing, then a deep code audit found and fixed 6 additional issues.

**Bugs found and fixed during demo testing:**

1. ✅ **Rust Docker image too old for Cargo.lock v4** — `deploy/docker/Dockerfile` used `rust:1.75` but `Cargo.lock` version 4 requires Rust 1.78+. Updated to `rust:1.85`.

2. ✅ **Missing `admin-fine-grained-authz` Keycloak feature** — Token exchange permission admin API calls failed silently. Added feature flag to both `keycloak-pic-spi/Dockerfile` build command and `docker-compose.yml` runtime command.

3. ✅ **`pic_ops` user attribute format breaks Trust Plane** — `realm-export.json` used JSON array string inside a single array element. Keycloak's protocol mapper with `multivalued: true` embeds this as one string. Changed to separate array elements.

4. ✅ **Demo script `p_0` check assumed username in value** — PrincipalExtractor uses `user.getId()` (UUID), not username. Updated demo to look up Alice's user ID via admin API.

5. ✅ **docker-compose.yml obsolete `version: "3.9"`** — Removed deprecated field.

6. ✅ **base64url decoding, curl error handling, base64 encoding** — Added `_b64url_decode()` helper for macOS/Linux compatibility, fixed `curl -sf` vs `curl -s` for error capture under `set -e`.

**Issues found and fixed during deep code audit:**

7. ✅ **Test realm `pic_ops` format mismatch** — `test-realm-pic.json` used JSON array string format while demo uses separate elements. Tests were exercising the wrong code path. Fixed to match production format.

8. ✅ **Non-existent `/pic/verify` endpoint advertised in well-known** — Removed `pca_verification_endpoint` from `PicRealmResource.getWellKnown()` since no such endpoint is implemented.

9. ✅ **Null safety for `subjectAccessToken.getSubject()`** — Added `UserModel` parameter to `buildPicTokenResponse()` with fallback to `user.getId()` when `getSubject()` returns null.

10. ✅ **Null guard in `PcaIssuanceResult.pcaHash()`** — Added null/empty check before Base64 decode to prevent NPE. Added 2 unit tests for this guard.

11. ✅ **Dead code in `handleTrustPlaneError`** — Changed return type from `Response` to `void` since the method either returns normally (fail-open) or throws (fail-closed). Simplified calling code and updated 2 unit tests.

12. ✅ **Redundant variable `subjectOtherClaimsForChain`** — Removed duplicate `getOtherClaims()` call in `buildPicTokenResponse()`.

**Demo scenarios verified (all 7 pass):**

| # | Scenario | Result |
|---|----------|--------|
| 1 | PIC discovery (`GET /pic/well-known`) | `pic_version: 1.0`, `pic_enabled: true` |
| 2 | Alice PIC token exchange | `typ: pic+jwt`, all PIC claims present |
| 3 | PROVENANCE — p_0 immutability | p_0 contains Alice's user UUID |
| 4 | IDENTITY — ops narrowing | Narrowed to `["read:claims:alice/claim-001"]` |
| 5 | Confused deputy BLOCKED | HTTP 403, `error: access_denied` |
| 6 | PIC introspection | `active: true`, `chain_length: 1`, `pca_valid: true` |
| 7 | CONTINUITY — pic_chain | `hop: 0`, `executor: pic-gateway`, `pca_hash` present |

**Issues found and fixed during deep edge-case testing (round 3):**

13. ✅ **NPE in `validateSubjectToken` when token decode returns null** — `session.tokens().decode()` can return `null` (not throw) for invalid tokens, causing NPE on `accessToken.getSessionId()` downstream. The Java exception message leaked in the HTTP 400 error_description. Added explicit null check after decode with clean error message.

14. ✅ **Keycloak log warnings about non-existent client scopes** — `realm-export.json` referenced `web-origins`, `acr`, `profile`, `roles`, `email` in `defaultClientScopes` but these built-in scopes are not available during `--import-realm`. Removed non-existent scope references, keeping only `pic-operations`.

15. ✅ **`cat_kid: null` in well-known response** — The well-known endpoint included `cat_kid: null` which is misleading since `cat_kid` is per-PCA (set by the Trust Plane during issuance), not a realm-level discovery value. Removed from well-known response; updated unit test to assert absence.

16. ✅ **Deprecated `KEYCLOAK_ADMIN` env vars in docker-compose.yml** — Keycloak 26.0 warns about deprecated `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` env vars. Updated to `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`.

**Manual edge cases verified (all 13 pass):**

| # | Edge Case | Result |
|---|-----------|--------|
| 1 | Bob PIC token exchange (read-only ops) | `pic_ops: ["read:claims:bob/*"]` |
| 2 | Bob tries to write (scope escalation) | HTTP 403 `access_denied` |
| 3 | Alice exchange with no scope param | Gets full authorized ops |
| 4 | Introspect with garbage token | `active: false` |
| 5 | Introspect with empty token | HTTP 400 |
| 6 | Introspect with no auth header | HTTP 401 |
| 7 | Introspect with wrong client secret | HTTP 401 |
| 8 | Introspect a standard (non-PIC) access token | `active: false` |
| 9 | Well-known confirms no `pca_verification_endpoint` | Absent |
| 10 | Standard token exchange (non-PIC) doesn't trigger SPI | Normal exchange |
| 11 | Multi-scope exchange (both read and write) | Both ops present |
| 12 | Exchange with invalid subject_token | HTTP 400 (clean error message) |
| 13 | Exchange with missing subject_token | HTTP 400 |

**Issues found and fixed during deep code audit (round 4):**

Comprehensive 5-agent parallel audit of all SPI source files, tests, demo scripts, Dockerfiles, and realm configs. 9 real issues identified and fixed:

17. ✅ **Missing Base64 decode error handling in `pcaHash()`** — If the Trust Plane returns invalid Base64 in the PCA field, `Base64.getDecoder().decode()` throws `IllegalArgumentException` which was uncaught. Added explicit catch with clear `IllegalStateException` message. Added unit test.

18. ✅ **Missing JSON parse error handling in `TrustPlaneClient.listExecutorKeys()`** — `objectMapper.readValue()` could throw `JsonProcessingException` on malformed response JSON. The exception would fall through to the `IOException` catch block and be misclassified as `UNREACHABLE` instead of `INVALID_RESPONSE`. Added explicit inner try-catch for correct error classification.

19. ✅ **Trust Plane Dockerfile HEALTHCHECK uses curl but curl not installed** — `deploy/docker/Dockerfile` used `curl -f` in HEALTHCHECK but `debian:bookworm-slim` doesn't include curl. Added `curl` to the `apt-get install` alongside `ca-certificates`.

20. ✅ **Information leak in `validateSubjectToken` error messages** — Exception messages from token decode were directly concatenated into the OAuth error response (`"Invalid subject token: " + e.getMessage()`), potentially leaking internal details like JWT signature algorithm, key ID, or stack traces. Changed to generic message and log the detail at DEBUG level.

21. ✅ **URL path injection in `TrustPlaneClient.revokeExecutorKey()`** — The `kid` parameter was concatenated directly into the URL path without encoding. Special characters (`/`, `?`, `#`) could cause path traversal or request misrouting. Added `URLEncoder.encode()`.

22. ✅ **demo.sh missing error checks in narrowing scenario** — Scenario 4 (scope narrowing) had no error check after the token exchange curl call. If the exchange failed, the script would continue with invalid data. Added error check matching the pattern used in other scenarios. Also added token extraction validation for Alice's initial login.

23. ✅ **docker-compose.yml missing `depends_on`** — Keycloak service did not declare dependency on trust-plane, leaving startup order to chance. Added `depends_on: - trust-plane`.

24. ✅ **Unused variable in `PicAdminResource.updateConfig()`** — `currentAttrs = realm.getAttributes()` was assigned but never used. Removed.

25. ✅ **demo.sh temp file not cleaned up** — `/tmp/pic-demo-blocked.json` written in Scenario 5 was not removed by the cleanup trap. Added `rm -f` to the cleanup function.

> **E2E demo verified (round 4):** 275 unit tests + 25 integration tests passing (300 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing against live Keycloak 26.0 + Trust Plane containers. 25 bugs/issues found and fixed across 4 testing rounds. Zero ERROR-level messages in Keycloak logs.

**Issues found and fixed during deep null-safety and edge-case audit (round 5):**

Targeted audit of OpsResolver wildcard matching, PrincipalExtractor act-chain handling, and PicEventListenerProvider audit event parsing. 7 issues identified and fixed:

26. ✅ **NPE in `OpsResolver.opIsCovered()` with null `op` parameter** — If `intersectOps()` was called with a `requestedOps` list containing null elements, `op.startsWith(prefix)` on line 184 would throw NPE. Added null/blank guard at method entry returning `false`.

27. ✅ **NPE in `OpsResolver.opIsCovered()` with null elements in `authorizedOps`** — If `authorizedOps` contained null entries (e.g., from a user attribute with null values in the list), `allowed.equals(op)` on line 177 would NPE. Added `continue` guard for null elements.

28. ✅ **NPE in `OpsResolver.intersectOps()` with null/blank `requestedOps` elements** — Null or blank elements in `requestedOps` would pass through to `opIsCovered()` and potentially be included in results. Added explicit null/blank skip in the loop.

29. ✅ **Malformed principal ID with null issuer in `PrincipalExtractor`** — If `extractPrincipal()` was called with a null or blank `issuer`, `String.format(PRINCIPAL_FORMAT_OIDC, issuer, subject)` would produce `"oidc:null#alice"` — a syntactically valid but semantically wrong principal ID. Added explicit issuer validation throwing `MISSING_PRINCIPAL` error.

30. ✅ **`StringIndexOutOfBoundsException` in `PicEventListenerProvider.parseOpsFromDetail()`** — If `opsStr` was `"["` (opening bracket without closing), `opsStr.substring(1, opsStr.length() - 1)` would throw because `length() - 1 = 0 < 1`. Fixed by requiring both `startsWith("[")` AND `endsWith("]")` before attempting JSON array parsing.

31. ✅ **Empty strings in space-delimited ops parsing** — `List.of(opsStr.split("\\s+"))` could include empty strings when `opsStr` starts or ends with whitespace (e.g., `" read:* "`). Changed to `ArrayList` with explicit empty-string filtering.

32. ✅ **Over-broad admin event matching for user attribute changes** — Any admin event on `users/{id}/attributes` was treated as PIC-relevant, even when changing unrelated attributes like `locale`. Narrowed to only match when the event representation actually contains `pic_ops`.

33. ✅ **Silent parsing failure in `parseOpsFromDetail()`** — When JSON array parsing fails (e.g., malformed brackets), the catch block silently fell through to space-delimited parsing. Added `LOG.warnv()` to log the parse failure for debugging.

> **Deep audit verified (round 5):** 287 unit tests + 25 integration tests passing (312 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing. 33 bugs/issues found and fixed across 5 testing rounds. Zero ERROR-level messages in Keycloak logs.

**Issues found and fixed during comprehensive 5-agent parallel audit (round 6):**

Full codebase audit by 5 parallel agents covering: (1) PicTokenExchangeProvider exchange flow, (2) TrustPlaneClient and models, (3) demo script and realm config, (4) REST endpoints (PicRealmResource, PicAdminResource), (5) protocol mapper and SPI wiring. ~60 findings triaged; 3 real bugs fixed, 1 doc mismatch corrected:

34. ✅ **Missing JsonProcessingException catch in `TrustPlaneClient.healthCheck()`** — If the Trust Plane returns HTTP 200 with malformed JSON (e.g., HTML error page from a proxy), `objectMapper.readValue()` throws `JsonProcessingException` which was uncaught. The `healthCheck()` method's contract is to always return a `TrustPlaneStatus` (never throw `TrustPlaneException`), so this violated the API contract. Fixed by wrapping in try-catch, returning `TrustPlaneStatus(false, "invalid_response", null, latencyMs)` on parse failure. Added unit test with WireMock.

35. ✅ **demo.sh missing PIC_TOKEN extraction validation** — After extracting `PIC_TOKEN` from the exchange response on line 378, there was no validation that the token was actually present. If `.access_token` was missing (e.g., due to an unreported error), subsequent `decode_jwt_header`/`decode_jwt_payload` calls would produce garbage output. Added `// empty` fallback to jq and explicit null/empty check with error message.

36. ✅ **demo.sh missing NARROW_TOKEN extraction validation** — Same issue as #35 for the narrowed scope exchange in Scenario 4. `NARROW_TOKEN` extracted on line 492 without validation. Added matching null/empty check.

37. ✅ **PicAdminResource.updateConfig() Javadoc mismatch** — Javadoc stated `@return 204 No Content on success` but the method actually returns `200 OK` with the updated configuration body. Fixed Javadoc to document the actual behavior: `@return 200 OK with the updated configuration`.

> **Comprehensive audit verified (round 6):** 288 unit tests + 25 integration tests passing (313 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing. 37 bugs/issues found and fixed across 6 testing rounds. Zero ERROR-level messages in Keycloak logs.

**Issues found and fixed during 4-agent deep audit (round 7):**

Deep audit by 4 parallel agents covering: (1) PicTokenExchangeProvider exchange flow and multi-hop logic, (2) demo.sh and Docker Compose robustness, (3) Trust Plane API compatibility (Java DTOs vs Rust API), (4) test coverage gaps. ~50 findings triaged; 8 real bugs fixed, 1 new test added. Additionally identified 3 critical design issues documented below.

38. ✅ **demo.sh `wait` returns immediately** — After printing "Press Ctrl+C to stop", the script called `wait` with no arguments. Since Docker Compose runs detached (`docker compose up -d`), there are no background jobs to wait for, so `wait` returns immediately, the script exits, and the cleanup trap fires — tearing down the demo before the user can interact. Fixed by replacing `wait` with `while true; do sleep 1; done` for proper blocking until Ctrl+C.

39. ✅ **demo.sh no `pipefail` masks build failures** — `set -e` without `pipefail` means `mvn clean package 2>&1 | tail -5` has exit status of `tail` (always 0), masking Maven build failures. Similarly for `cargo build | tail` and `docker compose up 2>&1 | tail`. Fixed by changing `set -e` to `set -eo pipefail`.

40. ✅ **demo.sh `$?` check unreachable under `set -e`** — `ALICE_TOKEN_RESPONSE=$(keycloak_login "alice" "alice123")` followed by `if [ $? -ne 0 ]` — under `set -e`, if `keycloak_login` fails, the script exits at the assignment line before reaching the `$?` check. The friendly error message was dead code. Fixed by changing to `if ! ALICE_TOKEN_RESPONSE=$(keycloak_login ...) || [ -z "$ALICE_TOKEN_RESPONSE" ]` which suppresses `set -e` within the `if` condition.

41. ✅ **PicAdminResource.updateConfig() non-atomic attribute setting** — The method iterated entries in a single loop, calling `realm.setAttribute()` THEN checking the next entry's key prefix. If a mix of valid `pic_` and invalid attributes was sent, valid ones got set before the invalid one caused a 400 error, leaving the realm in a partially modified state. Fixed with two-pass approach: validate ALL keys first, then set them only if all pass. Added new test `updateConfig_rejectsNonPicAttributes_atomically` verifying `verify(realm, never()).setAttribute(anyString(), anyString())` when any key is invalid.

42. ✅ **buildFailOpenTokenResponse() missing subject null-fallback** — `buildPicTokenResponse()` has a fallback: if `getSubject()` returns null, check `otherClaims.get("sub")`. `buildFailOpenTokenResponse()` used `getSubject()` directly without the same fallback, potentially producing a JWT with null `sub` claim when fail-open triggers. Fixed by adding the same `otherClaims` check.

43. ✅ **buildPicTokenResponse() empty catKid ternary** — `pcaResult.getOps().isEmpty() ? "" : extractCatKid(pcaResult)` — the `cat_kid` should always come from the Trust Plane regardless of whether ops is empty. The PCA is signed regardless. An empty `cat_kid` in `pic_provenance` would break downstream verification. Fixed by always calling `extractCatKid(pcaResult)`.

44. ✅ **demo.sh base64 line-wrapping** — `tr -d '\n'` only strips newlines but not carriage returns. On some platforms (notably macOS with certain locales) `base64` wraps with `\r\n`. Fixed by changing to `tr -d '\n\r'`.

45. ✅ **docker-compose depends_on without healthcheck condition** — `depends_on: - trust-plane` only ensures the container starts, not that it's healthy. The trust-plane Dockerfile has a `HEALTHCHECK` instruction, but without `condition: service_healthy`, Keycloak could start before Trust Plane's `/health` endpoint returns 200. Fixed by adding `condition: service_healthy`.

> **Deep audit verified (round 7):** 289 unit tests + 25 integration tests passing (314 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing. 45 bugs/issues found and fixed across 7 testing rounds.

**Issues found and fixed during exchange() coverage testing (round 8):**

Addressed the CRITICAL test coverage gap identified in round 7: the `exchange()` method and its direct dependencies (`validateSubjectToken()`, `findUserSession()`, `buildFailOpenTokenResponse()`, `getRealmIssuer()`) had zero test coverage. Added 25 new unit tests covering all exchange flow paths. Also found and fixed 1 residual security bug.

46. ✅ **Residual information leak in `exchange()` catch-all** — The `exchange()` method's catch-all `Exception e` block at lines 167-173 concatenated `e.getMessage()` into the OAuth error response: `"Subject token validation failed: " + e.getMessage()`. While bug #20 (round 4) fixed the same issue inside `validateSubjectToken()`, the outer catch-all in `exchange()` itself was missed. Any unexpected exception from `findUserSession()` or `userSession.getUser()` would leak internal details. Fixed by using generic message `"Subject token validation failed"` (exception details already logged at WARN level).

**New test coverage added (25 tests):**

- **ValidateSubjectTokenTests** (3 tests): Token decode success, null decode result → 400, decode throws → 400
- **FindUserSessionTests** (5 tests): Session found by ID, fallback to user by ID, fallback to user by username, no user found → 400, null session/subject → 400
- **BuildFailOpenTokenResponseTests** (2 tests): Standard token returned with Bearer type, otherClaims sub fallback when getSubject() returns null
- **ExchangeTests** (13 tests): No Trust Plane URL → 500, blank Trust Plane URL → 500, null subject token → 400, blank subject token → 400, token decode failure → 400, no valid ops → 403, Trust Plane unreachable (fail-closed) → throws, Trust Plane unreachable (fail-open) → Bearer token returned, successful PCA issuance → reaches signing step, principal extraction failure → 400, multi-hop → calls processPoc (not issuePca), requested scope narrows ops, executor name falls back to clientId
- **GetRealmIssuerTests** (2 tests): Correct format with trailing slash, correct format without trailing slash

> **Exchange coverage verified (round 8):** 314 unit tests + 25 integration tests passing (339 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing. 46 bugs/issues found and fixed across 8 testing rounds. The `exchange()` method — the core business logic — now has comprehensive test coverage including all error paths, fail-open/fail-closed behavior, multi-hop detection, scope narrowing, and executor name fallback.

**Issues found and fixed during deep audit of demo and REST endpoints (round 9):**

Two-agent parallel audit covering: (1) demo.sh edge cases, race conditions, and error handling robustness, (2) PicRealmResource and PicOpsProtocolMapper null safety, security, and test coverage. ~25 findings triaged; 2 real bugs fixed.

47. ✅ **demo.sh jq extracts "null" as string for missing UUIDs** — When `jq -r '.[0].id'` encounters a null value (e.g., because the realm hasn't finished importing), it outputs the string `"null"` instead of empty string. All subsequent admin API calls would silently fail with malformed URLs containing `"null"`. Fixed by using `jq -r '.[0].id // empty'` pattern for all UUID and ID extractions (RESOURCE_API_UUID, GATEWAY_UUID, REALM_MGMT_UUID, TOKEN_EXCHANGE_PERM_ID, POLICY_ID, RESOURCE_ID, SCOPE_ID). Also added validation check after extraction with explicit error reporting.

48. ✅ **demo.sh race condition with Keycloak realm import** — `wait_for_service` checks if `/realms/pic-demo` responds, but Keycloak may report the realm endpoint as available before the realm import is fully complete (clients, users, and SPI not yet loaded). Added retry logic: if client UUID extraction fails, wait 5 seconds and retry once. If still failing, exit with diagnostic output showing which UUIDs are missing.

> **Deep audit verified (round 9):** 314 unit tests + 25 integration tests passing (339 total), BUILD SUCCESS. Full Docker demo runs end-to-end with all 7 scenarios passing. 48 bugs/issues found and fixed across 9 testing rounds.

**Known design issues identified in round 7 (not yet fixed — require architectural decisions):**

1. **ProcessPocRequest API mismatch (CRITICAL for multi-hop):** The Java `TrustPlaneClient` sends `{ "predecessor_pca": "...", "requested_ops": [...], "executor_binding": {...} }` to `POST /v1/poc/process`, but the Rust Trust Plane expects a single `"poc"` field containing the COSE_Sign1 PoC structure. Multi-hop token exchange will fail at the Trust Plane API level. This requires either (a) updating the Rust API to accept the Java format, or (b) building a proper COSE_Sign1 PoC on the Java side before sending. Single-hop (hop 0) works because it uses `/v1/pca/issue` which has matching request format.

2. **cat_kid always null from Trust Plane responses:** The Rust `IssuePcaResponse` and `ProcessPocResponse` do not include a `cat_kid` field. The Java `extractCatKid()` method falls back to truncating the PCA hash to 16 characters. This works but produces an opaque identifier rather than the actual Trust Plane signing key ID.

3. **revokeExecutorKey DELETE endpoint non-functional:** The Java admin API calls `DELETE /v1/keys/executor/{kid}` but no corresponding route exists in the Rust Trust Plane router. Key revocation via the admin UI will return a 404/502 error. This endpoint needs to be added to the Rust `provenance-plane` crate.

---

## Appendix A: Sequence Diagrams

### A.1 Initial PIC Token Exchange

```
Client          Keycloak                    PicTokenExchangeProvider       Trust Plane
  │                │                                │                        │
  │ POST /token    │                                │                        │
  │ grant_type=    │                                │                        │
  │ token-exchange │                                │                        │
  │ requested_     │                                │                        │
  │ token_type=    │                                │                        │
  │ pic_token      │                                │                        │
  │───────────────►│                                │                        │
  │                │ supports()?                     │                        │
  │                │───────────────────────────────►│                        │
  │                │ true (pic_token + realm + client enabled)              │
  │                │◄───────────────────────────────│                        │
  │                │ exchange()                      │                        │
  │                │───────────────────────────────►│                        │
  │                │                                │ validate subject_token  │
  │                │                                │──┐                     │
  │                │                                │  │ extract p_0, ops    │
  │                │                                │◄─┘                     │
  │                │                                │                        │
  │                │                                │ POST /v1/pca/issue     │
  │                │                                │───────────────────────►│
  │                │                                │                        │ validate JWT
  │                │                                │                        │ extract p_0
  │                │                                │                        │ sign PCA_0
  │                │                                │  { pca, p_0, ops }     │
  │                │                                │◄───────────────────────│
  │                │                                │                        │
  │                │                                │ build PIC JWT         │
  │                │                                │ + pic_provenance      │
  │                │                                │ + pic_ops             │
  │                │                                │ + pic_chain           │
  │                │  { access_token, issued_token_type=pic_token }         │
  │                │◄───────────────────────────────│                        │
  │  PIC token     │                                │                        │
  │◄───────────────│                                │                        │
```

### A.2 Multi-Hop PIC Exchange (Successor)

```
Service A       Keycloak                    PicTokenExchangeProvider       Trust Plane
  │                │                                │                        │
  │ POST /token    │                                │                        │
  │ subject_token= │                                │                        │
  │ <PIC token     │                                │                        │
  │  from hop 0>   │                                │                        │
  │ requested_     │                                │                        │
  │ token_type=    │                                │                        │
  │ pic_token      │                                │                        │
  │ scope=narrowed │                                │                        │
  │───────────────►│                                │                        │
  │                │ exchange()                      │                        │
  │                │───────────────────────────────►│                        │
  │                │                                │ detect PIC token       │
  │                │                                │ (typ=pic+jwt)          │
  │                │                                │──┐                     │
  │                │                                │  │ extract predecessor │
  │                │                                │  │ PCA from            │
  │                │                                │  │ pic_provenance      │
  │                │                                │◄─┘                     │
  │                │                                │                        │
  │                │                                │ POST /v1/poc/process   │
  │                │                                │ { predecessor_pca,     │
  │                │                                │   requested_ops,       │
  │                │                                │   executor_binding }   │
  │                │                                │───────────────────────►│
  │                │                                │                        │ verify predecessor
  │                │                                │                        │ check monotonicity
  │                │                                │                        │ sign PCA_1
  │                │                                │  { pca, p_0, ops }     │
  │                │                                │◄───────────────────────│
  │                │                                │                        │
  │                │                                │ build PIC JWT (hop=1) │
  │                │  PIC token (hop=1)              │                        │
  │                │◄───────────────────────────────│                        │
  │  PIC token     │                                │                        │
  │◄───────────────│                                │                        │
```

---

## Appendix B: Error Responses

| Scenario | HTTP Status | OAuth Error | Description |
|----------|-------------|-------------|-------------|
| PIC not enabled for realm | 400 | `unsupported_token_type` | Realm does not support PIC tokens |
| PIC not enabled for client | 400 | `unauthorized_client` | Client not configured for PIC exchange |
| No valid operations | 403 | `access_denied` | Intersection of authorized and requested ops is empty |
| Trust Plane unreachable | 503 | `temporarily_unavailable` | Cannot reach Trust Plane (fail-closed) |
| Trust Plane timeout | 504 | `temporarily_unavailable` | Trust Plane did not respond in time |
| Trust Plane rejected | 403 | `access_denied` | Trust Plane refused to issue PCA (e.g., credential invalid) |
| Monotonicity violation | 403 | `access_denied` | Requested ops not subset of predecessor (multi-hop) |
| Invalid subject_token | 400 | `invalid_grant` | Subject token is expired, revoked, or malformed |
| Malformed act chain | 400 | `invalid_grant` | Act claim exceeds max depth or has no sub |

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **PIC** | Provenance Identity Continuity — cryptographic authority tracking through distributed systems |
| **PCA** | Proof of Causal Authority — the authority credential at a specific execution hop |
| **PCA_0** | Initial PCA issued at federation entry (hop 0) |
| **PoC** | Proof of Continuity — request from an executor for a successor PCA |
| **p_0** | Origin principal — the immutable identity of the human who initiated the request |
| **CAT** | Centralized Authority Tracker (Trust Plane) — signs PCAs and enforces invariants |
| **Trust Plane** | The PIC server that issues and validates PCAs (this project's `provenance-plane` crate) |
| **Federation Bridge** | Translates external credentials (JWT, API key) to PIC PCAs (`provenance-bridge` crate) |
| **WIMSE** | Workload Identity in Multi-System Environments — IETF working group for workload identity |
| **COSE_Sign1** | CBOR Object Signing (RFC 9052) — the signature format used for PCAs and PoCs |
| **Monotonicity** | The invariant that operations can only shrink: `ops_{i+1} ⊆ ops_i` |
| **Executor** | A service or agent that holds authority at a specific hop in the chain |
| **Executor Binding** | Key-value metadata identifying an executor (service name, agent ID, etc.) |

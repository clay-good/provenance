# Federation Demo

This demo shows two Trust Planes federating to share authority across organizational boundaries.

## Scenario

**Organizations:**
- **Acme Corp** - A company with its own Trust Plane
- **Partner Inc** - A partner organization with its own Trust Plane

**Story:**
1. Alice works at Acme Corp and has a PCA issued by Acme's Trust Plane
2. Alice needs to access Partner Inc's API as part of a business integration
3. Partner Inc has registered Acme Corp as a federated CAT
4. Partner Inc can verify Alice's PCA signed by Acme Corp
5. Authority flows securely across the federation boundary

## Running the Demo

```bash
./demo.sh
```

## What Happens

### 1. Two Trust Planes Start
- Acme Corp Trust Plane on port 8080
- Partner Inc Trust Plane on port 8081

### 2. Federation Setup
Partner Inc registers Acme Corp's CAT public key, enabling verification of Acme-issued PCAs.

### 3. Cross-Organization PCA Verification
- Alice gets a PCA from Acme Corp
- Partner Inc verifies the PCA is legitimately signed by Acme Corp's CAT
- Authority is preserved: p_0 (Alice) and ops cannot be escalated

### 4. Attack Prevention
- Forged/unknown CAT signatures are rejected
- Unregistered Trust Planes cannot issue valid PCAs

## Federation API

### GET /v1/federation/info
Returns this Trust Plane's info for discovery:
```json
{
  "kid": "acme-corp-cat",
  "public_key": "base64-encoded-ed25519-public-key",
  "name": "Acme Corp",
  "api_version": "v1",
  "features": ["pca_issuance", "poc_processing", "federation", "revocation"]
}
```

### POST /v1/federation/cats
Register a federated CAT:
```json
{
  "kid": "partner-cat",
  "public_key": "base64-encoded-ed25519-public-key",
  "name": "Partner Inc",
  "endpoint": "https://partner.example.com"
}
```

### GET /v1/federation/cats
List all registered CATs (local and federated).

### DELETE /v1/federation/cats/:kid
Unregister a federated CAT.

### POST /v1/federation/verify
Verify a PCA from any known Trust Plane:
```json
{
  "pca": "base64-encoded-signed-pca"
}
```

Response:
```json
{
  "valid": true,
  "issuer_kid": "acme-corp-cat",
  "issuer_known": true,
  "p_0": "custom:mock:alice",
  "hop": 0,
  "ops": ["read:partner:data:*", "write:partner:data:alice/*"]
}
```

### POST /v1/federation/discover
Auto-discover and register a Trust Plane by URL (requires `federation` feature):
```json
{
  "url": "https://partner.example.com"
}
```

## Security Properties

Federation preserves all PIC invariants:

1. **PROVENANCE (p_0 immutable)**: The origin principal cannot change across federation boundaries
2. **IDENTITY (ops shrink)**: Operations can only narrow, never expand across federation
3. **CONTINUITY (crypto chain)**: Each hop is cryptographically linked; federation adds CAT verification

## Production Considerations

- **CAT Key Rotation**: Plan for rotating federated CAT keys
- **Mutual TLS**: Use mTLS between federated Trust Planes
- **Revocation Sync**: Consider syncing revocation lists between federated planes
- **Discovery Security**: Validate endpoints before auto-discovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Federation Network                           │
│                                                                     │
│   ┌───────────────────┐           ┌───────────────────┐            │
│   │   Acme Corp       │           │   Partner Inc     │            │
│   │   Trust Plane     │◄─────────►│   Trust Plane     │            │
│   │                   │  CAT Keys  │                   │            │
│   │  CAT: acme-cat    │           │  CAT: partner-cat │            │
│   │                   │           │                   │            │
│   └─────────┬─────────┘           └─────────┬─────────┘            │
│             │                               │                       │
│             │ Issues PCA                    │ Verifies PCA          │
│             │                               │                       │
│             ▼                               ▼                       │
│   ┌─────────────────┐             ┌─────────────────┐              │
│   │   Alice's       │────────────►│   Partner API   │              │
│   │   Agent         │  PCA signed │                 │              │
│   │                 │  by Acme    │                 │              │
│   └─────────────────┘             └─────────────────┘              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

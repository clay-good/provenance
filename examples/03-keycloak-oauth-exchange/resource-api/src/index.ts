/**
 * Resource API - PCA-Protected Claims Resource Server
 *
 * The final enforcement point for PCA-based authorization.
 * This service:
 * 1. Receives requests with PCA in X-PIC-PCA header
 * 2. Decodes and extracts the PCA payload
 * 3. Checks if the requested operation is in the PCA's allowed ops
 * 4. Returns claims data only if authorized
 *
 * This is the LAST LINE OF DEFENSE. Even if the gateway and Keycloak
 * were both compromised, this service checks authority directly against
 * the cryptographic PCA chain — a confused deputy attack is blocked
 * because the PCA's ops are monotonically narrowed from p_0's original
 * authority and cannot be escalated.
 */

import express from 'express';
import { base64ToUint8Array } from '@provenance/sdk';
import { decode } from 'cborg';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.PORT ?? 3001;
const LOG_LEVEL = process.env.LOG_LEVEL ?? 'info';

// =============================================================================
// Logging
// =============================================================================

function log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  if (levels[level] >= (levels[LOG_LEVEL as keyof typeof levels] ?? 1)) {
    const prefix = `[Resource-API]`;
    if (data) {
      console.log(`${prefix} ${message}`, JSON.stringify(data));
    } else {
      console.log(`${prefix} ${message}`);
    }
  }
}

// =============================================================================
// Mock Claims Database
// =============================================================================

interface Claim {
  id: string;
  owner: string;
  type: string;
  status: string;
  amount: number;
  description: string;
  created_at: string;
  updated_at: string;
}

// Claims use {owner}/{claim-name} format to match PIC ops patterns.
// Alice has read:claims:alice/* → matches alice/claim-001, alice/claim-002
// Bob has read:claims:bob/* → matches bob/claim-001, bob/claim-002
const CLAIMS_DB: Map<string, Claim> = new Map([
  ['alice/claim-001', {
    id: 'alice/claim-001',
    owner: 'alice',
    type: 'auto',
    status: 'approved',
    amount: 5000,
    description: 'Fender bender on Main St - covered under comprehensive',
    created_at: '2024-01-15T10:30:00Z',
    updated_at: '2024-01-20T14:00:00Z',
  }],
  ['alice/claim-002', {
    id: 'alice/claim-002',
    owner: 'alice',
    type: 'health',
    status: 'pending',
    amount: 1500,
    description: 'Annual checkup and lab work',
    created_at: '2024-02-01T09:00:00Z',
    updated_at: '2024-02-01T09:00:00Z',
  }],
  ['bob/claim-001', {
    id: 'bob/claim-001',
    owner: 'bob',
    type: 'home',
    status: 'approved',
    amount: 25000,
    description: 'Water damage from burst pipe in basement',
    created_at: '2024-01-10T08:00:00Z',
    updated_at: '2024-01-25T16:30:00Z',
  }],
  ['bob/claim-002', {
    id: 'bob/claim-002',
    owner: 'bob',
    type: 'auto',
    status: 'denied',
    amount: 3000,
    description: 'Parking lot vandalism - not covered under basic plan',
    created_at: '2024-01-20T11:00:00Z',
    updated_at: '2024-01-22T10:00:00Z',
  }],
]);

// =============================================================================
// PCA Types and Helpers
// =============================================================================

interface PrincipalIdentifier {
  type: string;
  value: string;
}

interface Pca {
  hop: number;
  p_0: PrincipalIdentifier;
  ops: string[];
  executor: Record<string, string>;
  provenance?: unknown;
  constraints?: unknown;
}

/**
 * Decode PCA from COSE_Sign1 bytes
 *
 * Note: In production, you would verify the signature using the Trust Plane's
 * public key. For this demo, we decode the payload to inspect the authority.
 */
function decodePca(pcaBytes: Uint8Array): Pca {
  // COSE_Sign1 structure: [protected, unprotected, payload, signature]
  const decoded = decode(pcaBytes, {
    tags: {
      18: (value: unknown) => value, // COSE_Sign1 tag
    },
  } as { tags: Record<number, (value: unknown) => unknown> });

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  const payload = decoded[2] as Uint8Array;

  // The Trust Plane encodes the PCA payload as JSON inside a CBOR byte string.
  // Try JSON parse first, fall back to CBOR decode for forward compatibility.
  const payloadStr = Buffer.from(payload).toString('utf-8');
  if (payloadStr.startsWith('{')) {
    return JSON.parse(payloadStr) as Pca;
  }
  return decode(payload) as Pca;
}

/**
 * Check if an operation is covered by the PCA's allowed operations
 *
 * Supports wildcards:
 * - '*' matches everything
 * - 'read:claims:*' matches 'read:claims:alice/claim-001'
 * - 'read:claims:alice/*' matches 'read:claims:alice/claim-001'
 * - 'read:*' matches 'read:claims:alice/claim-001'
 */
function operationAllowed(allowedOps: string[], requiredOp: string): boolean {
  for (const op of allowedOps) {
    if (op === '*') {
      return true;
    }
    if (op === requiredOp) {
      return true;
    }
    // Handle wildcard patterns: 'read:claims:alice/*' or 'read:claims:*'
    if (op.endsWith('/*')) {
      const prefix = op.slice(0, -1); // Remove '*', keep '/'
      if (requiredOp.startsWith(prefix)) {
        return true;
      }
    }
    if (op.endsWith(':*')) {
      const prefix = op.slice(0, -1); // Remove '*', keep ':'
      if (requiredOp.startsWith(prefix)) {
        return true;
      }
    }
  }
  return false;
}

// =============================================================================
// Response Types
// =============================================================================

interface AuthorityHop {
  hop: number;
  service: string;
  ops: string[];
}

interface ClaimsResponse {
  claim_id: string;
  owner: string;
  data: Record<string, unknown>;
  authority_chain: AuthorityHop[];
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Resource API Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * GET /claims/:claimId
 *
 * Get a specific claim by ID. Requires PCA with read:claims:{claimId} permission.
 *
 * The claimId format is {owner}/{claim-name}, e.g., "alice/claim-001".
 * The PCA ops must cover this path — e.g., read:claims:alice/* authorizes
 * read:claims:alice/claim-001 but NOT read:claims:bob/claim-001.
 *
 * This is where the confused deputy attack is blocked: even if the gateway
 * tried to forward Alice's token to access Bob's claim, the PCA's ops
 * (which were monotonically narrowed from Alice's original authority)
 * would not cover read:claims:bob/*.
 */
app.get('/claims/:owner/:claimName', (req, res) => {
  const { owner, claimName } = req.params;
  const claimId = `${owner}/${claimName}`;
  const requiredOp = `read:claims:${claimId}`;

  log('info', `GET /claims/${claimId}`);

  // 1. Extract PCA from header
  const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
  if (!pcaHeader) {
    log('warn', 'REJECTED: Missing PCA header');
    return res.status(401).json({
      error: 'Missing authority',
      code: 'MISSING_PCA',
      details: { required_header: 'X-PIC-PCA' },
    } satisfies ErrorResponse);
  }

  // 2. Decode PCA
  let pca: Pca;
  try {
    const pcaBytes = base64ToUint8Array(pcaHeader);
    pca = decodePca(pcaBytes);
  } catch (error) {
    log('error', `REJECTED: Invalid PCA format - ${error}`);
    return res.status(400).json({
      error: 'Invalid PCA format',
      code: 'INVALID_PCA',
    } satisfies ErrorResponse);
  }

  log('info', `PCA decoded: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=[${pca.ops.join(', ')}]`);

  // 3. Check if operation is allowed by PCA
  if (!operationAllowed(pca.ops, requiredOp)) {
    log('warn', `REJECTED: Operation '${requiredOp}' not in allowed ops [${pca.ops.join(', ')}]`);
    log('warn', 'CONFUSED DEPUTY ATTACK BLOCKED by PIC authority chain!');
    return res.status(403).json({
      error: 'Operation not authorized',
      code: 'FORBIDDEN',
      details: {
        required_op: requiredOp,
        allowed_ops: pca.ops,
        p_0: pca.p_0.value,
        hop: pca.hop,
        message: 'The requested operation is not covered by the PCA. ' +
                 'This could indicate a confused deputy attack — the authority chain ' +
                 'traces back to a principal who does not have permission for this resource.',
      },
    } satisfies ErrorResponse);
  }

  // 4. Get claim from database
  const claim = CLAIMS_DB.get(claimId);
  if (!claim) {
    log('info', `Claim not found: ${claimId}`);
    return res.status(404).json({
      error: 'Claim not found',
      code: 'NOT_FOUND',
      details: { claim_id: claimId },
    } satisfies ErrorResponse);
  }

  // 5. Return claim data with authority chain
  log('info', `SUCCESS: Returning claim ${claimId} (authorized via PCA, p_0=${pca.p_0.value})`);

  const response: ClaimsResponse = {
    claim_id: claim.id,
    owner: claim.owner,
    data: {
      type: claim.type,
      status: claim.status,
      amount: claim.amount,
      description: claim.description,
      created_at: claim.created_at,
      updated_at: claim.updated_at,
    },
    authority_chain: [
      {
        hop: pca.hop,
        service: 'resource-api',
        ops: pca.ops,
      },
    ],
  };

  return res.json(response);
});

/**
 * GET /claims
 *
 * List all claims accessible by the PCA's operations.
 * Only returns claims where the PCA ops cover read:claims:{claimId}.
 */
app.get('/claims', (req, res) => {
  log('info', 'GET /claims (list all accessible)');

  // 1. Extract PCA from header
  const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
  if (!pcaHeader) {
    log('warn', 'REJECTED: Missing PCA header');
    return res.status(401).json({
      error: 'Missing authority',
      code: 'MISSING_PCA',
    } satisfies ErrorResponse);
  }

  // 2. Decode PCA
  let pca: Pca;
  try {
    const pcaBytes = base64ToUint8Array(pcaHeader);
    pca = decodePca(pcaBytes);
  } catch (error) {
    log('error', `REJECTED: Invalid PCA format - ${error}`);
    return res.status(400).json({
      error: 'Invalid PCA format',
      code: 'INVALID_PCA',
    } satisfies ErrorResponse);
  }

  log('info', `PCA decoded: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=[${pca.ops.join(', ')}]`);

  // 3. Filter claims based on PCA operations
  const accessibleClaims: Claim[] = [];
  for (const [id, claim] of CLAIMS_DB) {
    if (operationAllowed(pca.ops, `read:claims:${id}`)) {
      accessibleClaims.push(claim);
    }
  }

  log('info', `SUCCESS: Returning ${accessibleClaims.length}/${CLAIMS_DB.size} claims (filtered by PCA)`);

  return res.json({
    claims: accessibleClaims,
    total: accessibleClaims.length,
    authority_chain: [
      {
        hop: pca.hop,
        service: 'resource-api',
        ops: pca.ops,
      },
    ],
  });
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'resource-api',
    claims_count: CLAIMS_DB.size,
  });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  log('info', `Resource API listening on port ${PORT}`);
  log('info', `Mock database has ${CLAIMS_DB.size} claims`);
  log('info', 'Claims: ' + Array.from(CLAIMS_DB.keys()).join(', '));
});

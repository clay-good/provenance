/**
 * Claims Service
 *
 * The final enforcement point for PCA-based authorization.
 * This service:
 * 1. Receives requests with PCA in X-PIC-PCA header
 * 2. Decodes and extracts the PCA
 * 3. Checks if the requested operation is in the PCA's allowed ops
 * 4. Returns data only if authorized
 *
 * This is the LAST LINE OF DEFENSE. Even if everything upstream failed,
 * this service checks authority directly against the PCA.
 */

import express from 'express';
import { base64ToUint8Array } from '@provenance/sdk';
import { decode } from 'cborg';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.CLAIMS_PORT ?? 3002;

// =============================================================================
// Mock Claims Database
// =============================================================================

interface Claim {
  id: string;
  owner: string; // User ID who owns this claim
  type: string;
  status: string;
  amount: number;
  description: string;
  created_at: string;
  updated_at: string;
}

// Mock database of claims
const CLAIMS_DB: Map<string, Claim> = new Map([
  ['alice-001', {
    id: 'alice-001',
    owner: 'alice',
    type: 'auto',
    status: 'approved',
    amount: 5000,
    description: 'Fender bender on Main St',
    created_at: '2024-01-15T10:30:00Z',
    updated_at: '2024-01-20T14:00:00Z',
  }],
  ['alice-002', {
    id: 'alice-002',
    owner: 'alice',
    type: 'health',
    status: 'pending',
    amount: 1500,
    description: 'Annual checkup',
    created_at: '2024-02-01T09:00:00Z',
    updated_at: '2024-02-01T09:00:00Z',
  }],
  ['bob-001', {
    id: 'bob-001',
    owner: 'bob',
    type: 'home',
    status: 'approved',
    amount: 25000,
    description: 'Water damage from burst pipe',
    created_at: '2024-01-10T08:00:00Z',
    updated_at: '2024-01-25T16:30:00Z',
  }],
  ['bob-002', {
    id: 'bob-002',
    owner: 'bob',
    type: 'auto',
    status: 'denied',
    amount: 3000,
    description: 'Vandalism - not covered',
    created_at: '2024-01-20T11:00:00Z',
    updated_at: '2024-01-22T10:00:00Z',
  }],
  ['charlie-001', {
    id: 'charlie-001',
    owner: 'charlie',
    type: 'life',
    status: 'pending',
    amount: 100000,
    description: 'Policy claim',
    created_at: '2024-02-05T14:00:00Z',
    updated_at: '2024-02-05T14:00:00Z',
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
 * public key. For this demo, we just decode the payload.
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
  return decode(payload) as Pca;
}

/**
 * Check if an operation is covered by the PCA's allowed operations
 *
 * Supports wildcards:
 * - '*' matches everything
 * - 'read:claims:*' matches 'read:claims:alice-001'
 * - 'read:claims:alice/*' matches 'read:claims:alice-001', 'read:claims:alice-002'
 */
function operationAllowed(allowedOps: string[], requiredOp: string): boolean {
  for (const op of allowedOps) {
    if (op === '*') {
      return true;
    }
    if (op === requiredOp) {
      return true;
    }
    // Handle wildcard patterns
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
// Error Response
// =============================================================================

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Claims Service Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * GET /claims/:id
 *
 * Get a specific claim by ID. Requires PCA with read:claims:{id} permission.
 */
app.get('/claims/:id', (req, res) => {
  const claimId = req.params.id;
  const requiredOp = `read:claims:${claimId}`;

  console.log(`[Claims] GET /claims/${claimId}`);

  // 1. Extract PCA from header
  const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
  if (!pcaHeader) {
    console.log(`[Claims] REJECTED: Missing PCA header`);
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
    console.log(`[Claims] REJECTED: Invalid PCA format - ${error}`);
    return res.status(400).json({
      error: 'Invalid PCA format',
      code: 'INVALID_PCA',
    } satisfies ErrorResponse);
  }

  console.log(`[Claims] PCA: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}`);

  // 3. Check if operation is allowed
  if (!operationAllowed(pca.ops, requiredOp)) {
    console.log(`[Claims] REJECTED: Operation '${requiredOp}' not in allowed ops`);
    console.log(`[Claims] This is a CONFUSED DEPUTY ATTACK - blocked by PIC!`);
    return res.status(403).json({
      error: 'Operation not authorized',
      code: 'FORBIDDEN',
      details: {
        required_op: requiredOp,
        allowed_ops: pca.ops,
        p_0: pca.p_0.value,
        message: 'The requested operation is not covered by the PCA. ' +
                 'This could indicate a confused deputy attack.',
      },
    } satisfies ErrorResponse);
  }

  // 4. Get claim from database
  const claim = CLAIMS_DB.get(claimId);
  if (!claim) {
    return res.status(404).json({
      error: 'Claim not found',
      code: 'NOT_FOUND',
    } satisfies ErrorResponse);
  }

  console.log(`[Claims] SUCCESS: Returning claim ${claimId}`);
  return res.json({
    claim,
    authority: {
      p_0: pca.p_0.value,
      hop: pca.hop,
      verified: true,
    },
  });
});

/**
 * GET /claims
 *
 * List all claims. Requires PCA with read:claims:* permission.
 * Returns only claims that match the PCA's allowed operations.
 */
app.get('/claims', (req, res) => {
  console.log(`[Claims] GET /claims (list all)`);

  // 1. Extract PCA from header
  const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
  if (!pcaHeader) {
    console.log(`[Claims] REJECTED: Missing PCA header`);
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
    console.log(`[Claims] REJECTED: Invalid PCA format`);
    return res.status(400).json({
      error: 'Invalid PCA format',
      code: 'INVALID_PCA',
    } satisfies ErrorResponse);
  }

  console.log(`[Claims] PCA: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}`);

  // 3. Filter claims based on allowed operations
  const allowedClaims: Claim[] = [];
  for (const [id, claim] of CLAIMS_DB) {
    const readOp = `read:claims:${id}`;
    if (operationAllowed(pca.ops, readOp)) {
      allowedClaims.push(claim);
    }
  }

  console.log(`[Claims] SUCCESS: Returning ${allowedClaims.length} claims (filtered by PCA)`);
  return res.json({
    claims: allowedClaims,
    total: allowedClaims.length,
    authority: {
      p_0: pca.p_0.value,
      hop: pca.hop,
      verified: true,
    },
  });
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'claims-service' });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`[Claims] Claims Service listening on port ${PORT}`);
  console.log(`[Claims] Mock database has ${CLAIMS_DB.size} claims`);
});

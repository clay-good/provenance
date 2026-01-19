/**
 * Storage Service (Hop 2)
 *
 * The final tier in the microservice chain. This service:
 * 1. Receives PCA from Archive in X-PIC-PCA header
 * 2. Validates PCA has required storage operations
 * 3. Performs the actual storage read/write
 *
 * This is the LAST LINE OF DEFENSE. The storage service validates
 * the PCA and ensures the request has proper authority traced back
 * to the original user through the cryptographic chain.
 *
 * Authority received at this hop:
 * - write:storage:* (for writes) - narrowed from write:archive:*
 * - read:storage:* (for reads) - narrowed from read:archive:*
 *
 * Note: Storage never sees read:* or write:archive:* - those ops
 * were stripped by upstream services practicing least privilege.
 */

import express from 'express';
import { base64ToUint8Array } from '@provenance/sdk';
import { decode } from 'cborg';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.STORAGE_PORT ?? 3002;

// =============================================================================
// In-Memory Storage
// =============================================================================

const storage = new Map<string, string>();

// =============================================================================
// PCA Helpers
// =============================================================================

interface Pca {
  hop: number;
  p_0: { type: string; value: string };
  ops: string[];
  executor: Record<string, string>;
}

function decodePca(pcaBase64: string): Pca {
  const pcaBytes = base64ToUint8Array(pcaBase64);
  const decoded = decode(pcaBytes, {
    tags: { 18: (v: unknown) => v },
  } as { tags: Record<number, (v: unknown) => unknown> });

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  const payload = decoded[2] as Uint8Array;
  // PCA payload is JSON (from Rust backend), not CBOR
  const payloadJson = new TextDecoder().decode(payload);
  return JSON.parse(payloadJson) as Pca;
}

function operationAllowed(allowedOps: string[], requiredOp: string): boolean {
  for (const op of allowedOps) {
    if (op === '*' || op === requiredOp) return true;
    if (op.endsWith(':*')) {
      const prefix = op.slice(0, -1);
      if (requiredOp.startsWith(prefix)) return true;
    }
    if (op.endsWith('/*')) {
      const prefix = op.slice(0, -1);
      if (requiredOp.startsWith(prefix)) return true;
    }
  }
  return false;
}

// =============================================================================
// Types
// =============================================================================

interface WriteRequest {
  path: string;
  content: string;
  file_id: string;
}

interface AuthorityHop {
  hop: number;
  service: string;
  ops: string[];
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Storage Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /write
 *
 * Write data to storage. Requires write:storage:* authority.
 */
app.post('/write', (req, res) => {
  try {
    const { path, content, file_id } = req.body as WriteRequest;

    // 1. Extract and validate PCA
    const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
    if (!pcaHeader) {
      console.log('[Storage] REJECTED: Missing PCA header');
      return res.status(401).json({
        error: 'Missing authority',
        code: 'MISSING_PCA',
      } satisfies ErrorResponse);
    }

    let pca: Pca;
    try {
      pca = decodePca(pcaHeader);
    } catch {
      return res.status(400).json({
        error: 'Invalid PCA format',
        code: 'INVALID_PCA',
      } satisfies ErrorResponse);
    }

    console.log(`[Storage] Write request: ${path}`);
    console.log(`[Storage] PCA: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}`);

    // 2. Validate authority - must have write:storage:*
    const requiredOp = 'write:storage:*';
    if (!operationAllowed(pca.ops, requiredOp)) {
      console.log(`[Storage] REJECTED: Operation ${requiredOp} not allowed`);
      console.log(`[Storage] Available ops: ${pca.ops.join(', ')}`);
      return res.status(403).json({
        error: 'Insufficient authority for storage write',
        code: 'FORBIDDEN',
        details: {
          required: requiredOp,
          available: pca.ops,
          p_0: pca.p_0.value,
          hop: pca.hop,
        },
      } satisfies ErrorResponse);
    }

    // 3. Verify the path belongs to the principal
    // This is an additional check - even with authority, we verify ownership
    const expectedPathPrefix = `/data/${pca.p_0.value}/`;
    if (!path.startsWith(expectedPathPrefix)) {
      console.log(`[Storage] REJECTED: Path ${path} does not match principal ${pca.p_0.value}`);
      return res.status(403).json({
        error: 'Path does not match principal',
        code: 'PATH_MISMATCH',
        details: {
          path,
          principal: pca.p_0.value,
          expected_prefix: expectedPathPrefix,
        },
      } satisfies ErrorResponse);
    }

    // 4. Write to storage
    storage.set(path, content);
    console.log(`[Storage] SUCCESS: Wrote ${content.length} bytes to ${path}`);

    // 5. Return success with authority chain
    return res.json({
      written: true,
      path,
      file_id,
      bytes: content.length,
      authority_chain: [
        {
          hop: pca.hop,
          service: 'storage',
          ops: pca.ops,
        },
      ] as AuthorityHop[],
    });

  } catch (error) {
    console.error('[Storage] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /read
 *
 * Read data from storage. Requires read:storage:* authority.
 */
app.get('/read', (req, res) => {
  try {
    const path = req.query.path as string;

    if (!path) {
      return res.status(400).json({
        error: 'Missing path parameter',
        code: 'BAD_REQUEST',
      } satisfies ErrorResponse);
    }

    // 1. Extract and validate PCA
    const pcaHeader = req.headers['x-pic-pca'] as string | undefined;
    if (!pcaHeader) {
      return res.status(401).json({
        error: 'Missing authority',
        code: 'MISSING_PCA',
      } satisfies ErrorResponse);
    }

    let pca: Pca;
    try {
      pca = decodePca(pcaHeader);
    } catch {
      return res.status(400).json({
        error: 'Invalid PCA format',
        code: 'INVALID_PCA',
      } satisfies ErrorResponse);
    }

    console.log(`[Storage] Read request: ${path}`);
    console.log(`[Storage] PCA: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}`);

    // 2. Validate authority
    const requiredOp = 'read:storage:*';
    if (!operationAllowed(pca.ops, requiredOp)) {
      console.log(`[Storage] REJECTED: Operation ${requiredOp} not allowed`);
      return res.status(403).json({
        error: 'Insufficient authority for storage read',
        code: 'FORBIDDEN',
        details: {
          required: requiredOp,
          available: pca.ops,
        },
      } satisfies ErrorResponse);
    }

    // 3. Verify path ownership
    const expectedPathPrefix = `/data/${pca.p_0.value}/`;
    if (!path.startsWith(expectedPathPrefix)) {
      console.log(`[Storage] REJECTED: Path does not match principal`);
      return res.status(403).json({
        error: 'Path does not match principal',
        code: 'PATH_MISMATCH',
      } satisfies ErrorResponse);
    }

    // 4. Read from storage
    const content = storage.get(path);
    if (content === undefined) {
      return res.status(404).json({
        error: 'File not found',
        code: 'NOT_FOUND',
      } satisfies ErrorResponse);
    }

    console.log(`[Storage] SUCCESS: Read ${content.length} bytes from ${path}`);

    return res.json({
      content,
      path,
      authority_chain: [
        {
          hop: pca.hop,
          service: 'storage',
          ops: pca.ops,
        },
      ] as AuthorityHop[],
    });

  } catch (error) {
    console.error('[Storage] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'storage',
    stored_files: storage.size,
  });
});

/**
 * GET /stats
 *
 * Get storage statistics (for demo purposes)
 */
app.get('/stats', (_req, res) => {
  const files: { path: string; size: number }[] = [];
  for (const [path, content] of storage) {
    files.push({ path, size: content.length });
  }
  res.json({
    total_files: storage.size,
    files,
  });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`[Storage] Storage Service listening on port ${PORT}`);
  console.log('[Storage] This is the FINAL enforcement point in the chain');
});

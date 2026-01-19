/**
 * Archive Service (Hop 1)
 *
 * The middle tier in the microservice chain. This service:
 * 1. Receives PCA from Gateway in X-PIC-PCA header
 * 2. Validates it has the required operations
 * 3. Builds PoC requesting only what Storage needs
 * 4. Gets successor PCA from Trust Plane
 * 5. Calls Storage service with the successor PCA
 *
 * This demonstrates authority NARROWING at each hop:
 * - Receives: write:archive:* (from Gateway)
 * - Requests: write:storage:* (only what Storage needs)
 */

import express from 'express';
import {
  TrustPlaneClient,
  TrustPlaneApiError,
  PocBuilder,
  generateKeyPair,
  base64ToUint8Array,
  type KeyPair,
} from '@provenance/sdk';
import { decode } from 'cborg';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.ARCHIVE_PORT ?? 3001;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const STORAGE_URL = process.env.STORAGE_URL ?? 'http://localhost:3002';

// =============================================================================
// State
// =============================================================================

let archiveKeyPair: KeyPair;
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

// In-memory archive index (maps file_id to storage path)
const archiveIndex = new Map<string, { path: string; metadata: Record<string, string> }>();

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

interface StoreRequest {
  filename: string;
  content: string;
  metadata?: Record<string, string>;
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
// Archive Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /store
 *
 * Store a file: Archive processes it and forwards to Storage
 */
app.post('/store', async (req, res) => {
  try {
    const { filename, content, metadata } = req.body as StoreRequest;

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
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid PCA format',
        code: 'INVALID_PCA',
      } satisfies ErrorResponse);
    }

    console.log(`[Archive] Store request: ${filename}`);
    console.log(`[Archive] PCA: hop=${pca.hop}, p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}`);

    // 2. Check if we have authority to write to archive
    const requiredOp = 'write:archive:*';
    if (!operationAllowed(pca.ops, requiredOp)) {
      console.log(`[Archive] REJECTED: ${requiredOp} not in allowed ops`);
      return res.status(403).json({
        error: 'Insufficient authority for archive write',
        code: 'FORBIDDEN',
        details: {
          required: requiredOp,
          available: pca.ops,
        },
      } satisfies ErrorResponse);
    }

    // 3. Generate file ID and storage path
    const fileId = `file-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const storagePath = `/data/${pca.p_0.value}/${filename}`;

    // 4. Build PoC for Storage - requesting ONLY storage operations
    // This is the key: we had write:archive:*, but we only pass write:storage:*
    const storageOps = ['write:storage:*'];
    console.log(`[Archive] Requesting successor PCA with ops: ${storageOps.join(', ')}`);

    const signedPoc = await new PocBuilder(pcaHeader)
      .withOps(storageOps)
      .withExecutor({
        service: 'archive',
        downstream: 'storage',
        file_id: fileId,
      })
      .sign(archiveKeyPair);

    // 5. Get successor PCA from Trust Plane
    let pca2Response;
    try {
      pca2Response = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        console.log(`[Archive] Trust Plane rejected: ${error.code} - ${error.message}`);
        return res.status(403).json({
          error: 'Cannot delegate to storage',
          code: error.code,
          details: { message: error.message },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    console.log(`[Archive] PCA_2 issued: hop=${pca2Response.hop}, ops=${pca2Response.ops.join(', ')}`);

    // 6. Call Storage service
    const storageResponse = await fetch(`${STORAGE_URL}/write`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PIC-PCA': pca2Response.pca,
      },
      body: JSON.stringify({
        path: storagePath,
        content,
        file_id: fileId,
      }),
    });

    if (!storageResponse.ok) {
      const errorBody = await storageResponse.json().catch(() => ({})) as ErrorResponse;
      return res.status(storageResponse.status).json({
        error: 'Storage service failed',
        code: errorBody.code ?? 'STORAGE_ERROR',
        details: errorBody as unknown as Record<string, unknown>,
      } satisfies ErrorResponse);
    }

    const storageResult = await storageResponse.json() as {
      written: boolean;
      path: string;
      authority_chain: AuthorityHop[];
    };

    // 7. Update archive index
    archiveIndex.set(fileId, {
      path: storagePath,
      metadata: metadata ?? {},
    });

    // 8. Return response with authority chain
    return res.json({
      file_id: fileId,
      path: storagePath,
      authority_chain: [
        { hop: 1, service: 'archive', ops: pca.ops },
        ...storageResult.authority_chain,
      ],
    });

  } catch (error) {
    console.error('[Archive] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /retrieve/:fileId
 *
 * Retrieve a file: Archive looks up path and forwards to Storage
 */
app.get('/retrieve/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;

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

    console.log(`[Archive] Retrieve request: ${fileId}`);
    console.log(`[Archive] PCA: hop=${pca.hop}, ops=${pca.ops.join(', ')}`);

    // 2. Check authority
    if (!operationAllowed(pca.ops, 'read:archive:*')) {
      return res.status(403).json({
        error: 'Insufficient authority for archive read',
        code: 'FORBIDDEN',
      } satisfies ErrorResponse);
    }

    // 3. Look up file in archive index
    const archiveEntry = archiveIndex.get(fileId);
    if (!archiveEntry) {
      return res.status(404).json({
        error: 'File not found in archive',
        code: 'NOT_FOUND',
      } satisfies ErrorResponse);
    }

    // 4. Build PoC for Storage
    const storageOps = ['read:storage:*'];
    const signedPoc = await new PocBuilder(pcaHeader)
      .withOps(storageOps)
      .withExecutor({
        service: 'archive',
        downstream: 'storage',
        operation: 'read',
      })
      .sign(archiveKeyPair);

    // 5. Get successor PCA
    let pca2Response;
    try {
      pca2Response = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        return res.status(403).json({
          error: 'Cannot delegate to storage',
          code: error.code,
        } satisfies ErrorResponse);
      }
      throw error;
    }

    // 6. Call Storage service
    const storageResponse = await fetch(
      `${STORAGE_URL}/read?path=${encodeURIComponent(archiveEntry.path)}`,
      {
        headers: { 'X-PIC-PCA': pca2Response.pca },
      }
    );

    if (!storageResponse.ok) {
      const errorBody = await storageResponse.json().catch(() => ({})) as ErrorResponse;
      return res.status(storageResponse.status).json(errorBody);
    }

    const storageResult = await storageResponse.json() as {
      content: string;
      authority_chain: AuthorityHop[];
    };

    return res.json({
      file_id: fileId,
      content: storageResult.content,
      metadata: archiveEntry.metadata,
      authority_chain: [
        { hop: 1, service: 'archive', ops: pca.ops },
        ...storageResult.authority_chain,
      ],
    });

  } catch (error) {
    console.error('[Archive] Error:', error);
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
    service: 'archive',
    key_id: archiveKeyPair?.kid ?? 'not initialized',
    indexed_files: archiveIndex.size,
  });
});

// =============================================================================
// Initialization
// =============================================================================

async function initialize() {
  console.log('[Archive] Initializing Archive Service...');

  archiveKeyPair = await generateKeyPair('archive-key');
  console.log(`[Archive] Generated key pair: ${archiveKeyPair.kid}`);

  try {
    await trustPlane.registerExecutorKey(archiveKeyPair.kid, archiveKeyPair.publicKey);
    console.log('[Archive] Registered with Trust Plane');
  } catch (error) {
    console.error('[Archive] Failed to register:', error);
  }

  app.listen(PORT, () => {
    console.log(`[Archive] Archive Service listening on port ${PORT}`);
    console.log(`[Archive] Trust Plane: ${TRUST_PLANE_URL}`);
    console.log(`[Archive] Storage Service: ${STORAGE_URL}`);
  });
}

initialize().catch(console.error);

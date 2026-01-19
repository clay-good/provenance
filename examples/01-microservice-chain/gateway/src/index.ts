/**
 * Gateway Service (Hop 0)
 *
 * The entry point for user requests. This service:
 * 1. Authenticates the user (mock JWT)
 * 2. Issues PCA_0 from Trust Plane with user's granted operations
 * 3. Builds PoC requesting only the ops needed for Archive
 * 4. Gets successor PCA from Trust Plane
 * 5. Calls Archive service with the successor PCA
 *
 * This demonstrates the FIRST hop in the authority chain, where
 * operations are scoped down to only what downstream needs.
 */

import express from 'express';
import {
  TrustPlaneClient,
  TrustPlaneApiError,
  PocBuilder,
  generateKeyPair,
  type KeyPair,
  type IssuePcaRequest,
} from '@provenance/sdk';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.GATEWAY_PORT ?? 3000;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const ARCHIVE_URL = process.env.ARCHIVE_URL ?? 'http://localhost:3001';

// =============================================================================
// State
// =============================================================================

let gatewayKeyPair: KeyPair;
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

// =============================================================================
// Mock JWT Validation
// =============================================================================

interface UserClaims {
  sub: string;
  name: string;
  scopes: string[];
}

function validateMockJwt(token: string): UserClaims | null {
  if (token.startsWith('mock:')) {
    const userId = token.slice(5);
    // Different users have different permissions
    const scopesByUser: Record<string, string[]> = {
      alice: ['read:*', 'write:archive:*', 'write:storage:*'],
      bob: ['read:archive:*'], // Bob can only read, not write
      admin: ['read:*', 'write:*', 'delete:*'],
    };
    return {
      sub: userId,
      name: userId.charAt(0).toUpperCase() + userId.slice(1),
      scopes: scopesByUser[userId] ?? ['read:*'],
    };
  }
  return null;
}

// =============================================================================
// Request/Response Types
// =============================================================================

interface UploadRequest {
  filename: string;
  content: string;
  metadata?: Record<string, string>;
}

interface UploadResponse {
  success: boolean;
  file_id: string;
  path: string;
  authority_chain: AuthorityHop[];
}

interface ReadRequest {
  file_id: string;
}

interface ReadResponse {
  success: boolean;
  file_id: string;
  content: string;
  metadata: Record<string, string>;
  authority_chain: AuthorityHop[];
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
// Gateway Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /upload
 *
 * Upload a file through the chain: Gateway -> Archive -> Storage
 *
 * Authority flow:
 * - PCA_0: ops = user's full permissions (e.g., [read:*, write:archive:*, write:storage:*])
 * - PCA_1 (for Archive): ops = [write:archive:*] (only what Archive needs)
 */
app.post('/upload', async (req, res) => {
  try {
    const { filename, content, metadata } = req.body as UploadRequest;

    if (!filename || !content) {
      return res.status(400).json({
        error: 'Missing filename or content',
        code: 'BAD_REQUEST',
      } satisfies ErrorResponse);
    }

    // 1. Extract and validate token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Missing Authorization header',
        code: 'UNAUTHORIZED',
      } satisfies ErrorResponse);
    }

    const token = authHeader.slice(7);
    const userClaims = validateMockJwt(token);
    if (!userClaims) {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      } satisfies ErrorResponse);
    }

    console.log(`[Gateway] Upload request from ${userClaims.sub}: ${filename}`);
    console.log(`[Gateway] User scopes: ${userClaims.scopes.join(', ')}`);

    // 2. Issue PCA_0 from Trust Plane with user's full permissions
    const issuePcaRequest: IssuePcaRequest = {
      credential: token,
      credential_type: 'mock',
      ops: userClaims.scopes,
      executor_binding: {
        service: 'gateway',
        user_id: userClaims.sub,
        operation: 'upload',
        filename,
      },
    };

    let pca0Response;
    try {
      pca0Response = await trustPlane.issuePca(issuePcaRequest);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        return res.status(502).json({
          error: 'Failed to issue authority',
          code: 'TRUST_PLANE_ERROR',
          details: { message: error.message },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    console.log(`[Gateway] PCA_0 issued: hop=${pca0Response.hop}, ops=${pca0Response.ops.join(', ')}`);

    // 3. Build PoC requesting what Archive needs AND what it will pass downstream
    // KEY INSIGHT: Archive needs write:archive:* for itself, and write:storage:* to delegate to Storage
    const archiveOps = ['write:archive:*', 'write:storage:*'];
    console.log(`[Gateway] Requesting successor PCA with ops: ${archiveOps.join(', ')}`);

    const signedPoc = await new PocBuilder(pca0Response.pca)
      .withOps(archiveOps)
      .withExecutor({
        service: 'gateway',
        downstream: 'archive',
        operation: 'upload',
      })
      .sign(gatewayKeyPair);

    // 4. Get successor PCA from Trust Plane
    let pca1Response;
    try {
      pca1Response = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        console.log(`[Gateway] Trust Plane rejected PoC: ${error.code}`);
        return res.status(403).json({
          error: 'Authority delegation failed',
          code: error.code,
          details: { message: error.message },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    console.log(`[Gateway] PCA_1 issued: hop=${pca1Response.hop}, ops=${pca1Response.ops.join(', ')}`);

    // 5. Call Archive service with successor PCA
    const archiveResponse = await fetch(`${ARCHIVE_URL}/store`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PIC-PCA': pca1Response.pca,
      },
      body: JSON.stringify({ filename, content, metadata }),
    });

    if (!archiveResponse.ok) {
      const errorBody = await archiveResponse.json().catch(() => ({})) as ErrorResponse;
      return res.status(archiveResponse.status).json({
        error: 'Archive service failed',
        code: errorBody.code ?? 'ARCHIVE_ERROR',
        details: errorBody as unknown as Record<string, unknown>,
      } satisfies ErrorResponse);
    }

    const archiveResult = await archiveResponse.json() as {
      file_id: string;
      path: string;
      authority_chain: AuthorityHop[];
    };

    // 6. Build response with full authority chain
    const response: UploadResponse = {
      success: true,
      file_id: archiveResult.file_id,
      path: archiveResult.path,
      authority_chain: [
        {
          hop: 0,
          service: 'gateway',
          ops: pca0Response.ops,
        },
        ...archiveResult.authority_chain,
      ],
    };

    console.log(`[Gateway] Upload complete: ${archiveResult.file_id}`);
    return res.json(response);

  } catch (error) {
    console.error('[Gateway] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /read/:fileId
 *
 * Read a file through the chain: Gateway -> Archive -> Storage
 */
app.get('/read/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;

    // 1. Extract and validate token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Missing Authorization header',
        code: 'UNAUTHORIZED',
      } satisfies ErrorResponse);
    }

    const token = authHeader.slice(7);
    const userClaims = validateMockJwt(token);
    if (!userClaims) {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      } satisfies ErrorResponse);
    }

    console.log(`[Gateway] Read request from ${userClaims.sub}: ${fileId}`);

    // 2. Issue PCA_0
    const pca0Response = await trustPlane.issuePca({
      credential: token,
      credential_type: 'mock',
      ops: userClaims.scopes,
      executor_binding: {
        service: 'gateway',
        user_id: userClaims.sub,
        operation: 'read',
        file_id: fileId,
      },
    });

    console.log(`[Gateway] PCA_0 issued: ops=${pca0Response.ops.join(', ')}`);

    // 3. Build PoC for Archive (read operations only)
    const archiveOps = ['read:archive:*'];
    const signedPoc = await new PocBuilder(pca0Response.pca)
      .withOps(archiveOps)
      .withExecutor({
        service: 'gateway',
        downstream: 'archive',
        operation: 'read',
      })
      .sign(gatewayKeyPair);

    // 4. Get successor PCA
    let pca1Response;
    try {
      pca1Response = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        if (error.code === 'MONOTONICITY_VIOLATION') {
          return res.status(403).json({
            error: 'Read access denied',
            code: 'FORBIDDEN',
            details: {
              message: 'User does not have read permissions',
              required: archiveOps,
              available: pca0Response.ops,
            },
          } satisfies ErrorResponse);
        }
        throw error;
      }
      throw error;
    }

    // 5. Call Archive service
    const archiveResponse = await fetch(`${ARCHIVE_URL}/retrieve/${fileId}`, {
      headers: {
        'X-PIC-PCA': pca1Response.pca,
      },
    });

    if (!archiveResponse.ok) {
      const errorBody = await archiveResponse.json().catch(() => ({})) as ErrorResponse;
      return res.status(archiveResponse.status).json(errorBody);
    }

    const archiveResult = await archiveResponse.json() as {
      file_id: string;
      content: string;
      metadata: Record<string, string>;
      authority_chain: AuthorityHop[];
    };

    const response: ReadResponse = {
      success: true,
      file_id: archiveResult.file_id,
      content: archiveResult.content,
      metadata: archiveResult.metadata,
      authority_chain: [
        { hop: 0, service: 'gateway', ops: pca0Response.ops },
        ...archiveResult.authority_chain,
      ],
    };

    return res.json(response);

  } catch (error) {
    console.error('[Gateway] Error:', error);
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
    service: 'gateway',
    key_id: gatewayKeyPair?.kid ?? 'not initialized',
  });
});

// =============================================================================
// Initialization
// =============================================================================

async function initialize() {
  console.log('[Gateway] Initializing Gateway Service...');

  // Generate key pair
  gatewayKeyPair = await generateKeyPair('gateway-key');
  console.log(`[Gateway] Generated key pair: ${gatewayKeyPair.kid}`);

  // Register with Trust Plane
  try {
    await trustPlane.registerExecutorKey(gatewayKeyPair.kid, gatewayKeyPair.publicKey);
    console.log('[Gateway] Registered with Trust Plane');
  } catch (error) {
    console.error('[Gateway] Failed to register with Trust Plane:', error);
  }

  // Start server
  app.listen(PORT, () => {
    console.log(`[Gateway] Gateway Service listening on port ${PORT}`);
    console.log(`[Gateway] Trust Plane: ${TRUST_PLANE_URL}`);
    console.log(`[Gateway] Archive Service: ${ARCHIVE_URL}`);
  });
}

initialize().catch(console.error);

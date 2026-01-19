/**
 * Agent Gateway
 *
 * The gateway is the entry point for user requests. It:
 * 1. Authenticates the user (mock JWT validation)
 * 2. Issues PCA_0 from the Trust Plane with user-scoped operations
 * 3. Forwards the request to the AI agent runtime with the PCA
 *
 * This demonstrates the first hop in the authority chain.
 */

import express from 'express';
import {
  TrustPlaneClient,
  TrustPlaneApiError,
  type IssuePcaRequest,
} from '@provenance/sdk';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.GATEWAY_PORT ?? 3000;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const AGENT_URL = process.env.AGENT_URL ?? 'http://localhost:3001';

// =============================================================================
// Mock JWT Validation
// =============================================================================

interface UserClaims {
  sub: string; // User ID
  name: string;
  email: string;
  scope: string[];
}

/**
 * Mock JWT validation - in production, use proper JWT validation
 *
 * For demo purposes, we accept tokens in the format:
 * - "mock:alice" -> user alice
 * - "mock:bob" -> user bob
 */
function validateMockJwt(token: string): UserClaims | null {
  if (token.startsWith('mock:')) {
    const userId = token.slice(5);
    return {
      sub: userId,
      name: userId.charAt(0).toUpperCase() + userId.slice(1),
      email: `${userId}@example.com`,
      scope: ['read:claims', 'write:claims'],
    };
  }
  return null;
}

// =============================================================================
// Request/Response Types
// =============================================================================

interface AskRequest {
  question: string;
}

interface AskResponse {
  answer: string;
  hop: number;
  p_0: string;
  ops_granted: string[];
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

// Trust Plane client
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

/**
 * POST /ask
 *
 * Main endpoint for user questions. Flow:
 * 1. Extract and validate JWT from Authorization header
 * 2. Issue PCA_0 from Trust Plane with user-scoped operations
 * 3. Forward to AI agent with PCA
 * 4. Return agent's response
 */
app.post('/ask', async (req, res) => {
  try {
    const { question } = req.body as AskRequest;

    if (!question) {
      return res.status(400).json({
        error: 'Missing question',
        code: 'MISSING_QUESTION',
      } satisfies ErrorResponse);
    }

    // 1. Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Missing or invalid Authorization header',
        code: 'UNAUTHORIZED',
      } satisfies ErrorResponse);
    }

    const token = authHeader.slice(7);

    // 2. Validate JWT (mock validation for demo)
    const userClaims = validateMockJwt(token);
    if (!userClaims) {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      } satisfies ErrorResponse);
    }

    console.log(`[Gateway] User authenticated: ${userClaims.sub}`);

    // 3. Issue PCA_0 from Trust Plane
    // CRITICAL: We scope operations to ONLY this user's claims
    const ops = [
      `read:claims:${userClaims.sub}/*`,  // Can read their own claims
      `write:claims:${userClaims.sub}/*`, // Can write their own claims
    ];

    console.log(`[Gateway] Requesting PCA_0 with ops: ${ops.join(', ')}`);

    const issuePcaRequest: IssuePcaRequest = {
      credential: token,
      credential_type: 'mock',
      ops,
      executor_binding: {
        service: 'gateway',
        user_id: userClaims.sub,
        request_id: crypto.randomUUID(),
      },
    };

    let pca0Response;
    try {
      pca0Response = await trustPlane.issuePca(issuePcaRequest);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        console.error(`[Gateway] Trust Plane error: ${error.code} - ${error.message}`);
        return res.status(502).json({
          error: 'Failed to issue authority',
          code: 'TRUST_PLANE_ERROR',
          details: { trustPlaneCode: error.code },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    console.log(`[Gateway] PCA_0 issued: hop=${pca0Response.hop}, p_0=${pca0Response.p_0}, ops=${pca0Response.ops.join(', ')}`);

    // 4. Forward request to AI agent with PCA
    console.log(`[Gateway] Forwarding to agent: ${AGENT_URL}/process`);

    const agentResponse = await fetch(`${AGENT_URL}/process`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PIC-PCA': pca0Response.pca,
      },
      body: JSON.stringify({
        question,
        user_id: userClaims.sub,
      }),
    });

    if (!agentResponse.ok) {
      const errorBody = await agentResponse.json().catch(() => ({}));
      console.error(`[Gateway] Agent error: ${agentResponse.status}`, errorBody);

      // Pass through agent errors
      return res.status(agentResponse.status).json({
        error: 'Agent processing failed',
        code: (errorBody as ErrorResponse).code ?? 'AGENT_ERROR',
        details: errorBody as Record<string, unknown>,
      } satisfies ErrorResponse);
    }

    const agentResult = await agentResponse.json() as { answer: string; hop: number; ops: string[] };

    // 5. Return response
    const response: AskResponse = {
      answer: agentResult.answer,
      hop: pca0Response.hop,
      p_0: pca0Response.p_0,
      ops_granted: pca0Response.ops,
    };

    console.log(`[Gateway] Request completed successfully`);
    return res.json(response);

  } catch (error) {
    console.error('[Gateway] Unexpected error:', error);
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
  res.json({ status: 'healthy', service: 'gateway' });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`[Gateway] Agent Gateway listening on port ${PORT}`);
  console.log(`[Gateway] Trust Plane URL: ${TRUST_PLANE_URL}`);
  console.log(`[Gateway] Agent URL: ${AGENT_URL}`);
});

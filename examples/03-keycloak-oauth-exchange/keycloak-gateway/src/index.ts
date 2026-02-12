/**
 * Keycloak Gateway - OAuth Token Exchange + PCA_0 Issuance
 *
 * Entry point for user requests. This service:
 * 1. Accepts requests with a standard OAuth Bearer token from Keycloak
 * 2. Performs OAuth Token Exchange (RFC 8693) with Keycloak to get an
 *    audience-scoped token targeting pic-resource-api
 * 3. Passes the exchanged token to the Trust Plane Federation Bridge
 *    to obtain PCA_0 (the token carries pic_ops and act claims)
 * 4. Builds a PoC to delegate authority to the resource-api
 * 5. Forwards the request with the successor PCA in the X-PIC-PCA header
 *
 * This demonstrates how OAuth Token Exchange naturally carries PIC
 * authority continuity: the act claim preserves the original user as p_0,
 * and pic_ops map directly to PIC operation strings.
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

const PORT = process.env.PORT ?? 3000;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const KEYCLOAK_URL = process.env.KEYCLOAK_URL ?? 'http://localhost:8180';
const RESOURCE_API_URL = process.env.RESOURCE_API_URL ?? 'http://localhost:3001';
const LOG_LEVEL = process.env.LOG_LEVEL ?? 'info';

// Keycloak OAuth client credentials (from realm-export.json)
const KEYCLOAK_REALM = 'pic-demo';
const KEYCLOAK_CLIENT_ID = 'pic-gateway';
const KEYCLOAK_CLIENT_SECRET = 'pic-gateway-secret';
const KEYCLOAK_AUDIENCE = 'pic-resource-api';

const KEYCLOAK_TOKEN_URL = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;

// =============================================================================
// State
// =============================================================================

let gatewayKeyPair: KeyPair;
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

// =============================================================================
// Logging
// =============================================================================

function log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  if (levels[level] >= (levels[LOG_LEVEL as keyof typeof levels] ?? 1)) {
    const prefix = `[Keycloak-Gateway]`;
    if (data) {
      console.log(`${prefix} ${message}`, JSON.stringify(data));
    } else {
      console.log(`${prefix} ${message}`);
    }
  }
}

// =============================================================================
// OAuth Token Exchange (RFC 8693)
// =============================================================================

interface TokenExchangeResponse {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

interface TokenExchangeError {
  error: string;
  error_description?: string;
}

/**
 * Perform OAuth Token Exchange with Keycloak (RFC 8693)
 *
 * Exchanges the user's access token for a new token scoped to the
 * pic-resource-api audience. The resulting token carries:
 * - act.sub = original user subject (preserves provenance)
 * - pic_ops = user's PIC operations from their Keycloak attributes
 * - aud = pic-resource-api (audience targeting)
 */
async function performTokenExchange(subjectToken: string): Promise<TokenExchangeResponse> {
  log('debug', 'Performing OAuth Token Exchange', {
    tokenUrl: KEYCLOAK_TOKEN_URL,
    audience: KEYCLOAK_AUDIENCE,
  });

  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: KEYCLOAK_CLIENT_ID,
    client_secret: KEYCLOAK_CLIENT_SECRET,
    subject_token: subjectToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    audience: KEYCLOAK_AUDIENCE,
  });

  const response = await fetch(KEYCLOAK_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({})) as TokenExchangeError;
    log('error', 'Token exchange failed', {
      status: response.status,
      error: errorBody.error,
      description: errorBody.error_description,
    });
    throw new Error(
      `Token exchange failed: ${errorBody.error ?? response.statusText}` +
      (errorBody.error_description ? ` - ${errorBody.error_description}` : '')
    );
  }

  const result = await response.json() as TokenExchangeResponse;
  log('debug', 'Token exchange succeeded', {
    issued_token_type: result.issued_token_type,
    expires_in: result.expires_in,
    scope: result.scope,
  });

  return result;
}

/**
 * Decode a JWT payload without verification (for logging/extracting claims)
 * Actual verification is done by the Trust Plane Federation Bridge.
 */
function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
  return JSON.parse(payload);
}

// =============================================================================
// Request/Response Types
// =============================================================================

interface ClaimsResponse {
  claim_id: string;
  owner: string;
  data: Record<string, unknown>;
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
 * GET /claims/:claimId
 *
 * Main endpoint for accessing claims. Flow:
 * 1. Extract Bearer token from Authorization header
 * 2. Perform OAuth Token Exchange with Keycloak (RFC 8693)
 * 3. Pass exchanged token to Trust Plane to get PCA_0
 * 4. Build PoC to delegate to resource-api with appropriate ops
 * 5. Forward to resource-api with successor PCA
 */
app.get('/claims/:owner/:claimName', async (req, res) => {
  try {
    const claimId = `${req.params.owner}/${req.params.claimName}`;

    // 1. Extract Bearer token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Missing or invalid Authorization header',
        code: 'UNAUTHORIZED',
      } satisfies ErrorResponse);
    }

    const userToken = authHeader.slice(7);

    // Decode the user token to log the subject (for demo visibility)
    let userSub: string;
    try {
      const userClaims = decodeJwtPayload(userToken);
      userSub = userClaims.preferred_username as string ?? userClaims.sub as string ?? 'unknown';
      log('info', `Request from user: ${userSub} for claim: ${claimId}`);
    } catch {
      userSub = 'unknown';
      log('info', `Request for claim: ${claimId} (could not decode user token)`);
    }

    // 2. Perform OAuth Token Exchange (RFC 8693)
    //    Exchange the user's token for one scoped to pic-resource-api
    //    The exchanged token will carry:
    //    - act.sub = original user (provenance preservation)
    //    - pic_ops = user's PIC operations
    log('info', 'Performing OAuth Token Exchange with Keycloak');

    let exchangeResult: TokenExchangeResponse;
    try {
      exchangeResult = await performTokenExchange(userToken);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      log('error', `Token exchange failed: ${message}`);
      return res.status(502).json({
        error: 'OAuth Token Exchange failed',
        code: 'TOKEN_EXCHANGE_FAILED',
        details: { message },
      } satisfies ErrorResponse);
    }

    // Log what the exchanged token carries (for demo visibility)
    try {
      const exchangedClaims = decodeJwtPayload(exchangeResult.access_token);
      log('info', 'Exchanged token claims', {
        sub: exchangedClaims.sub,
        act: exchangedClaims.act,
        pic_ops: exchangedClaims.pic_ops,
        aud: exchangedClaims.aud,
      });
    } catch {
      log('debug', 'Could not decode exchanged token for logging');
    }

    // 3. Issue PCA_0 via Trust Plane Federation Bridge
    //    The exchanged JWT carries pic_ops (from Keycloak user attributes)
    //    and the act claim (from token exchange). The JWT handler (extended
    //    in Step 4) extracts these to build PCA_0.
    log('info', 'Requesting PCA_0 from Trust Plane');

    // Extract pic_ops from the exchanged token to use as requested ops
    let requestedOps: string[];
    try {
      const exchangedClaims = decodeJwtPayload(exchangeResult.access_token);
      const picOps = exchangedClaims.pic_ops;
      if (Array.isArray(picOps)) {
        requestedOps = picOps as string[];
      } else if (typeof picOps === 'string') {
        requestedOps = [picOps];
      } else {
        // Fall back to extracting from scope claim
        const scope = exchangedClaims.scope;
        if (typeof scope === 'string') {
          requestedOps = scope.split(' ').filter((s: string) => s.startsWith('read:') || s.startsWith('write:'));
        } else {
          requestedOps = ['read:*'];
        }
      }
    } catch {
      requestedOps = ['read:*'];
    }

    log('info', `Requesting PCA_0 with ops: ${requestedOps.join(', ')}`);

    const issuePcaRequest: IssuePcaRequest = {
      credential: exchangeResult.access_token,
      credential_type: 'jwt',
      ops: requestedOps,
      executor_binding: {
        service: 'keycloak-gateway',
        user: userSub,
        operation: 'read',
        claim_id: claimId,
        token_exchange: 'keycloak',
      },
    };

    let pca0Response;
    try {
      pca0Response = await trustPlane.issuePca(issuePcaRequest);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        log('error', `Trust Plane error: ${error.code} - ${error.message}`);
        return res.status(502).json({
          error: 'Failed to issue authority',
          code: 'TRUST_PLANE_ERROR',
          details: { trustPlaneCode: error.code, message: error.message },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    log('info', `PCA_0 issued: hop=${pca0Response.hop}, p_0=${pca0Response.p_0}, ops=${pca0Response.ops.join(', ')}`);

    // 4. Build PoC to delegate authority to resource-api
    //    Only request the ops that the resource-api actually needs
    const resourceOps = pca0Response.ops; // Pass through all ops — resource-api will enforce
    log('info', `Building PoC for resource-api with ops: ${resourceOps.join(', ')}`);

    const signedPoc = await new PocBuilder(pca0Response.pca)
      .withOps(resourceOps)
      .withExecutor({
        service: 'keycloak-gateway',
        downstream: 'resource-api',
        operation: 'read',
        claim_id: claimId,
      })
      .sign(gatewayKeyPair);

    // Get successor PCA from Trust Plane
    let pca1Response;
    try {
      pca1Response = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        log('error', `Trust Plane rejected PoC: ${error.code} - ${error.message}`);
        return res.status(403).json({
          error: 'Authority delegation failed',
          code: error.code,
          details: { message: error.message },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    log('info', `PCA_1 issued: hop=${pca1Response.hop}, ops=${pca1Response.ops.join(', ')}`);

    // 5. Forward request to resource-api with PCA
    log('info', `Forwarding to resource-api: ${RESOURCE_API_URL}/claims/${claimId}`);

    const resourceResponse = await fetch(`${RESOURCE_API_URL}/claims/${claimId}`, {
      headers: {
        'X-PIC-PCA': pca1Response.pca,
      },
    });

    if (!resourceResponse.ok) {
      const errorBody = await resourceResponse.json().catch(() => ({})) as ErrorResponse;
      log('error', `Resource API error: ${resourceResponse.status}`, errorBody as unknown as Record<string, unknown>);
      return res.status(resourceResponse.status).json({
        error: 'Resource API request failed',
        code: errorBody.code ?? 'RESOURCE_API_ERROR',
        details: errorBody as unknown as Record<string, unknown>,
      } satisfies ErrorResponse);
    }

    const resourceResult = await resourceResponse.json() as ClaimsResponse;

    // Build response with full authority chain
    const response: ClaimsResponse = {
      claim_id: resourceResult.claim_id,
      owner: resourceResult.owner,
      data: resourceResult.data,
      authority_chain: [
        {
          hop: 0,
          service: 'keycloak-gateway',
          ops: pca0Response.ops,
        },
        ...resourceResult.authority_chain,
      ],
    };

    log('info', `Request completed: claim=${claimId}, user=${userSub}, p_0=${pca0Response.p_0}`);
    return res.json(response);

  } catch (error) {
    console.error('[Keycloak-Gateway] Unexpected error:', error);
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
    service: 'keycloak-gateway',
    key_id: gatewayKeyPair?.kid ?? 'not initialized',
    keycloak_url: KEYCLOAK_URL,
    trust_plane_url: TRUST_PLANE_URL,
  });
});

// =============================================================================
// Initialization
// =============================================================================

async function initialize() {
  log('info', 'Initializing Keycloak Gateway...');
  log('info', `Keycloak URL: ${KEYCLOAK_URL}`);
  log('info', `Trust Plane URL: ${TRUST_PLANE_URL}`);
  log('info', `Resource API URL: ${RESOURCE_API_URL}`);

  // Generate key pair for signing PoCs
  gatewayKeyPair = await generateKeyPair('keycloak-gateway-key');
  log('info', `Generated key pair: ${gatewayKeyPair.kid}`);

  // Register with Trust Plane
  try {
    await trustPlane.registerExecutorKey(gatewayKeyPair.kid, gatewayKeyPair.publicKey);
    log('info', 'Registered executor key with Trust Plane');
  } catch (error) {
    log('error', 'Failed to register with Trust Plane', {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  // Start server
  app.listen(PORT, () => {
    log('info', `Keycloak Gateway listening on port ${PORT}`);
    log('info', `Token exchange endpoint: ${KEYCLOAK_TOKEN_URL}`);
  });
}

initialize().catch(console.error);

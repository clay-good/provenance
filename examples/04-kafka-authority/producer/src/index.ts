/**
 * Kafka Producer with PIC Authority
 *
 * This producer demonstrates embedding PCA in Kafka message headers.
 * Each message carries cryptographic authority that proves:
 * 1. WHO originally authorized the message (p_0)
 * 2. WHAT operations are allowed (ops)
 * 3. The authority chain from user -> producer
 *
 * Key concept: The producer requests write:kafka:{topic}:* authority
 * from the Trust Plane before producing messages. The PCA is then
 * embedded in the message header so consumers can validate.
 *
 * This prevents:
 * - Unauthorized message injection
 * - Authority escalation through message queues
 * - Confused deputy attacks via async messaging
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

const PORT = process.env.PRODUCER_PORT ?? 3001;
const TRUST_PLANE_URL = process.env.TRUST_PLANE_URL ?? 'http://localhost:8080';
const BROKER_URL = process.env.BROKER_URL ?? 'http://localhost:9092';

// =============================================================================
// State
// =============================================================================

let producerKeyPair: KeyPair;
const trustPlane = new TrustPlaneClient(TRUST_PLANE_URL);

// =============================================================================
// Mock Authentication
// =============================================================================

interface UserClaims {
  sub: string;
  name: string;
  scopes: string[];
}

function validateMockJwt(token: string): UserClaims | null {
  if (token.startsWith('mock:')) {
    const userId = token.slice(5);
    // Different users have different Kafka permissions
    const scopesByUser: Record<string, string[]> = {
      // Alice can write to orders topic
      alice: ['write:kafka:orders:*', 'write:kafka:events:*'],
      // Bob can only read (no produce permission)
      bob: ['read:kafka:orders:*'],
      // Admin has full access
      admin: ['write:kafka:*', 'read:kafka:*'],
      // Analytics service can write to analytics topic only
      analytics: ['write:kafka:analytics:*'],
    };
    return {
      sub: userId,
      name: userId.charAt(0).toUpperCase() + userId.slice(1),
      scopes: scopesByUser[userId] ?? [],
    };
  }
  return null;
}

// =============================================================================
// Types
// =============================================================================

interface ProduceRequest {
  topic: string;
  key: string;
  value: string;
  metadata?: Record<string, string>;
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Producer Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /produce
 *
 * Produce a message to Kafka with PCA authority embedded in headers.
 *
 * Authority flow:
 * 1. User authenticates with JWT
 * 2. Producer issues PCA_0 with user's Kafka scopes
 * 3. Producer builds PoC for specific topic/key
 * 4. Trust Plane returns successor PCA with narrowed ops
 * 5. Message is sent to Kafka with PCA in header
 */
app.post('/produce', async (req, res) => {
  try {
    const { topic, key, value, metadata } = req.body as ProduceRequest;

    if (!topic || !key || value === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: topic, key, value',
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

    console.log(`[Producer] Produce request from ${userClaims.sub}: topic=${topic}, key=${key}`);
    console.log(`[Producer] User scopes: ${userClaims.scopes.join(', ')}`);

    // Check if user has any Kafka write permissions
    const hasWritePermission = userClaims.scopes.some(s => s.startsWith('write:kafka:'));
    if (!hasWritePermission) {
      console.log(`[Producer] REJECTED: ${userClaims.sub} has no Kafka write permissions`);
      return res.status(403).json({
        error: 'No Kafka write permissions',
        code: 'FORBIDDEN',
        details: {
          user: userClaims.sub,
          available_scopes: userClaims.scopes,
          required: 'write:kafka:*',
        },
      } satisfies ErrorResponse);
    }

    // 2. Issue PCA_0 from Trust Plane
    const issuePcaRequest: IssuePcaRequest = {
      credential: token,
      credential_type: 'mock',
      ops: userClaims.scopes,
      executor_binding: {
        service: 'kafka-producer',
        user_id: userClaims.sub,
        operation: 'produce',
        topic,
        key,
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

    console.log(`[Producer] PCA_0 issued: hop=${pca0Response.hop}, ops=${pca0Response.ops.join(', ')}`);

    // 3. Build PoC requesting authority for this specific topic
    // KEY INSIGHT: We request only write:kafka:{topic}:* not broader permissions
    const requestedOps = [`write:kafka:${topic}:*`];
    console.log(`[Producer] Requesting successor PCA with ops: ${requestedOps.join(', ')}`);

    const signedPoc = await new PocBuilder(pca0Response.pca)
      .withOps(requestedOps)
      .withExecutor({
        service: 'kafka-producer',
        operation: 'produce',
        topic,
        key,
        timestamp: Date.now().toString(),
      })
      .sign(producerKeyPair);

    // 4. Get successor PCA from Trust Plane
    let successorResponse;
    try {
      successorResponse = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        console.log(`[Producer] Trust Plane REJECTED: ${error.code} - ${error.message}`);
        return res.status(403).json({
          error: 'Authority delegation failed',
          code: error.code,
          details: {
            message: error.message,
            requested_ops: requestedOps,
            available_ops: pca0Response.ops,
          },
        } satisfies ErrorResponse);
      }
      throw error;
    }

    console.log(`[Producer] Successor PCA issued: hop=${successorResponse.hop}, ops=${successorResponse.ops.join(', ')}`);

    // 5. Produce message to Kafka with PCA in header
    const kafkaResponse = await fetch(`${BROKER_URL}/produce`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        topic,
        key,
        value,
        headers: {
          'x-pic-pca': successorResponse.pca,
          'x-pic-p0': userClaims.sub,
          ...metadata,
        },
      }),
    });

    if (!kafkaResponse.ok) {
      const errorBody = await kafkaResponse.json().catch(() => ({}));
      return res.status(kafkaResponse.status).json({
        error: 'Kafka broker error',
        code: 'BROKER_ERROR',
        details: errorBody,
      } satisfies ErrorResponse);
    }

    const kafkaResult = await kafkaResponse.json() as {
      success: boolean;
      topic: string;
      partition: number;
      offset: number;
      timestamp: number;
    };

    console.log(`[Producer] SUCCESS: Produced to ${topic}, partition=${kafkaResult.partition}, offset=${kafkaResult.offset}`);

    return res.json({
      success: true,
      topic: kafkaResult.topic,
      partition: kafkaResult.partition,
      offset: kafkaResult.offset,
      timestamp: kafkaResult.timestamp,
      authority: {
        p_0: userClaims.sub,
        ops: successorResponse.ops,
        hop: successorResponse.hop,
      },
    });

  } catch (error) {
    console.error('[Producer] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * POST /produce-batch
 *
 * Produce multiple messages with a single authority grant.
 * Demonstrates authority reuse within a transaction.
 */
app.post('/produce-batch', async (req, res) => {
  try {
    const { topic, messages } = req.body as {
      topic: string;
      messages: Array<{ key: string; value: string }>;
    };

    // Extract token
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

    console.log(`[Producer] Batch produce from ${userClaims.sub}: ${messages.length} messages to ${topic}`);

    // Issue PCA_0
    const pca0Response = await trustPlane.issuePca({
      credential: token,
      credential_type: 'mock',
      ops: userClaims.scopes,
      executor_binding: {
        service: 'kafka-producer',
        operation: 'batch-produce',
        topic,
        message_count: messages.length.toString(),
      },
    });

    // Get successor PCA for this topic
    const signedPoc = await new PocBuilder(pca0Response.pca)
      .withOps([`write:kafka:${topic}:*`])
      .withExecutor({
        service: 'kafka-producer',
        operation: 'batch-produce',
        topic,
      })
      .sign(producerKeyPair);

    let successorResponse;
    try {
      successorResponse = await trustPlane.processPoc(signedPoc);
    } catch (error) {
      if (error instanceof TrustPlaneApiError) {
        return res.status(403).json({
          error: 'Authority delegation failed',
          code: error.code,
        } satisfies ErrorResponse);
      }
      throw error;
    }

    // Produce all messages with the same PCA
    const results = [];
    for (const msg of messages) {
      const kafkaResponse = await fetch(`${BROKER_URL}/produce`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          topic,
          key: msg.key,
          value: msg.value,
          headers: {
            'x-pic-pca': successorResponse.pca,
            'x-pic-p0': userClaims.sub,
          },
        }),
      });

      const result = await kafkaResponse.json();
      results.push(result);
    }

    return res.json({
      success: true,
      topic,
      produced: results.length,
      results,
      authority: {
        p_0: userClaims.sub,
        ops: successorResponse.ops,
      },
    });

  } catch (error) {
    console.error('[Producer] Batch error:', error);
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
    service: 'kafka-producer',
    key_id: producerKeyPair?.kid ?? 'not initialized',
  });
});

// =============================================================================
// Initialization
// =============================================================================

async function initialize() {
  console.log('[Producer] Initializing Kafka Producer...');

  producerKeyPair = await generateKeyPair('kafka-producer-key');
  console.log(`[Producer] Generated key pair: ${producerKeyPair.kid}`);

  try {
    await trustPlane.registerExecutorKey(producerKeyPair.kid, producerKeyPair.publicKey);
    console.log('[Producer] Registered with Trust Plane');
  } catch (error) {
    console.error('[Producer] Failed to register:', error);
  }

  app.listen(PORT, () => {
    console.log(`[Producer] Kafka Producer listening on port ${PORT}`);
    console.log(`[Producer] Trust Plane: ${TRUST_PLANE_URL}`);
    console.log(`[Producer] Broker: ${BROKER_URL}`);
  });
}

initialize().catch(console.error);

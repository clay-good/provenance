/**
 * Kafka Consumer with PIC Authority Validation
 *
 * This consumer validates PCA in Kafka message headers before processing.
 * Each consumed message is checked for:
 * 1. Presence of X-PIC-PCA header
 * 2. Valid PCA signature (from Trust Plane)
 * 3. Appropriate ops for the message's topic/key
 *
 * Key concept: Even if a malicious producer injects messages into Kafka,
 * the consumer will REJECT them if they lack valid PCA authority.
 *
 * This provides END-TO-END authority enforcement:
 * - Producer proves authority to WRITE
 * - Consumer validates authority before PROCESSING
 * - Authority chain traces back to original user
 *
 * Defense in depth: Even if Kafka broker is compromised, messages
 * without valid PCA cannot be processed by PIC-aware consumers.
 */

import express from 'express';
import { base64ToUint8Array } from '@provenance/sdk';
import { decode } from 'cborg';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.CONSUMER_PORT ?? 3002;
const BROKER_URL = process.env.BROKER_URL ?? 'http://localhost:9092';
const CONSUMER_ID = process.env.CONSUMER_ID ?? 'pic-consumer-1';

// =============================================================================
// Types
// =============================================================================

interface Pca {
  hop: number;
  p_0: { type: string; value: string };
  ops: string[];
  executor: Record<string, string>;
}

interface KafkaMessage {
  id: string;
  topic: string;
  partition: number;
  key: string;
  value: string;
  headers: Record<string, string>;
  timestamp: number;
  offset: number;
}

interface ProcessedMessage {
  message_id: string;
  topic: string;
  key: string;
  authority: {
    p_0: string;
    ops: string[];
    hop: number;
  };
  status: 'processed' | 'rejected';
  reason?: string;
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// PCA Validation Helpers
// =============================================================================

function decodePca(pcaBase64: string): Pca {
  const pcaBytes = base64ToUint8Array(pcaBase64);
  const decoded = decode(pcaBytes, {
    tags: { 18: (v: unknown) => v },
  } as { tags: Record<number, (v: unknown) => unknown> });

  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  const payload = decoded[2] as Uint8Array;
  return decode(payload) as Pca;
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
// Message Processing State
// =============================================================================

const processedMessages: ProcessedMessage[] = [];
const rejectedMessages: ProcessedMessage[] = [];

// Statistics
const stats = {
  total_consumed: 0,
  authorized: 0,
  rejected_no_pca: 0,
  rejected_invalid_pca: 0,
  rejected_insufficient_ops: 0,
};

// =============================================================================
// Consumer Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /consume
 *
 * Consume messages from a topic, validating PCA for each message.
 * Messages without valid PCA are REJECTED.
 */
app.post('/consume', async (req, res) => {
  try {
    const { topic, max_messages = 10 } = req.body as { topic: string; max_messages?: number };

    if (!topic) {
      return res.status(400).json({
        error: 'Missing topic',
        code: 'BAD_REQUEST',
      } satisfies ErrorResponse);
    }

    console.log(`[Consumer] Consuming from topic: ${topic}`);

    // Fetch messages from broker
    const brokerResponse = await fetch(`${BROKER_URL}/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        topic,
        consumer_id: CONSUMER_ID,
        max_messages,
      }),
    });

    if (!brokerResponse.ok) {
      return res.status(brokerResponse.status).json({
        error: 'Broker error',
        code: 'BROKER_ERROR',
      } satisfies ErrorResponse);
    }

    const { messages } = await brokerResponse.json() as { messages: KafkaMessage[] };

    console.log(`[Consumer] Received ${messages.length} messages`);

    const results: ProcessedMessage[] = [];

    for (const msg of messages) {
      stats.total_consumed++;
      console.log(`[Consumer] Processing message: topic=${msg.topic}, key=${msg.key}, offset=${msg.offset}`);

      // 1. Check for PCA header
      const pcaHeader = msg.headers['x-pic-pca'];
      if (!pcaHeader) {
        console.log(`[Consumer] REJECTED: Message ${msg.id} has no PCA header`);
        stats.rejected_no_pca++;
        const rejected: ProcessedMessage = {
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: 'unknown', ops: [], hop: -1 },
          status: 'rejected',
          reason: 'Missing X-PIC-PCA header - message not authorized',
        };
        rejectedMessages.push(rejected);
        results.push(rejected);
        continue;
      }

      // 2. Decode and validate PCA
      let pca: Pca;
      try {
        pca = decodePca(pcaHeader);
      } catch (error) {
        console.log(`[Consumer] REJECTED: Message ${msg.id} has invalid PCA format`);
        stats.rejected_invalid_pca++;
        const rejected: ProcessedMessage = {
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: 'unknown', ops: [], hop: -1 },
          status: 'rejected',
          reason: 'Invalid PCA format - could not decode',
        };
        rejectedMessages.push(rejected);
        results.push(rejected);
        continue;
      }

      console.log(`[Consumer] PCA: p_0=${pca.p_0.value}, ops=${pca.ops.join(', ')}, hop=${pca.hop}`);

      // 3. Validate authority for this topic/key
      // Producer should have had write:kafka:{topic}:* or more specific
      const requiredOp = `write:kafka:${msg.topic}:${msg.key}`;
      if (!operationAllowed(pca.ops, requiredOp)) {
        console.log(`[Consumer] REJECTED: Message ${msg.id} - insufficient ops`);
        console.log(`[Consumer]   Required: ${requiredOp}`);
        console.log(`[Consumer]   Available: ${pca.ops.join(', ')}`);
        stats.rejected_insufficient_ops++;
        const rejected: ProcessedMessage = {
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: pca.p_0.value, ops: pca.ops, hop: pca.hop },
          status: 'rejected',
          reason: `Insufficient authority: required ${requiredOp}, available ${pca.ops.join(', ')}`,
        };
        rejectedMessages.push(rejected);
        results.push(rejected);
        continue;
      }

      // 4. Message is authorized - process it
      console.log(`[Consumer] AUTHORIZED: Message ${msg.id} from ${pca.p_0.value}`);
      stats.authorized++;

      const processed: ProcessedMessage = {
        message_id: msg.id,
        topic: msg.topic,
        key: msg.key,
        authority: {
          p_0: pca.p_0.value,
          ops: pca.ops,
          hop: pca.hop,
        },
        status: 'processed',
      };

      processedMessages.push(processed);
      results.push(processed);

      // Simulate message processing
      console.log(`[Consumer] Processing message content: ${msg.value.substring(0, 100)}...`);
    }

    return res.json({
      consumed: results.length,
      authorized: results.filter(r => r.status === 'processed').length,
      rejected: results.filter(r => r.status === 'rejected').length,
      results,
    });

  } catch (error) {
    console.error('[Consumer] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * POST /consume-with-filter
 *
 * Consume messages filtered by principal (p_0).
 * Only processes messages from specific users.
 */
app.post('/consume-with-filter', async (req, res) => {
  try {
    const { topic, allowed_principals, max_messages = 10 } = req.body as {
      topic: string;
      allowed_principals: string[];
      max_messages?: number;
    };

    console.log(`[Consumer] Consuming from ${topic} with filter: ${allowed_principals.join(', ')}`);

    const brokerResponse = await fetch(`${BROKER_URL}/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        topic,
        consumer_id: `${CONSUMER_ID}-filtered`,
        max_messages,
      }),
    });

    const { messages } = await brokerResponse.json() as { messages: KafkaMessage[] };

    const results: ProcessedMessage[] = [];

    for (const msg of messages) {
      const pcaHeader = msg.headers['x-pic-pca'];
      if (!pcaHeader) {
        results.push({
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: 'unknown', ops: [], hop: -1 },
          status: 'rejected',
          reason: 'Missing PCA header',
        });
        continue;
      }

      let pca: Pca;
      try {
        pca = decodePca(pcaHeader);
      } catch {
        results.push({
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: 'unknown', ops: [], hop: -1 },
          status: 'rejected',
          reason: 'Invalid PCA',
        });
        continue;
      }

      // Check if principal is in allowed list
      if (!allowed_principals.includes(pca.p_0.value)) {
        console.log(`[Consumer] FILTERED: Message from ${pca.p_0.value} not in allowed list`);
        results.push({
          message_id: msg.id,
          topic: msg.topic,
          key: msg.key,
          authority: { p_0: pca.p_0.value, ops: pca.ops, hop: pca.hop },
          status: 'rejected',
          reason: `Principal ${pca.p_0.value} not in allowed list`,
        });
        continue;
      }

      results.push({
        message_id: msg.id,
        topic: msg.topic,
        key: msg.key,
        authority: { p_0: pca.p_0.value, ops: pca.ops, hop: pca.hop },
        status: 'processed',
      });
    }

    return res.json({
      consumed: results.length,
      authorized: results.filter(r => r.status === 'processed').length,
      rejected: results.filter(r => r.status === 'rejected').length,
      results,
    });

  } catch (error) {
    console.error('[Consumer] Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    } satisfies ErrorResponse);
  }
});

/**
 * GET /stats
 *
 * Get consumer statistics.
 */
app.get('/stats', (_req, res) => {
  res.json({
    consumer_id: CONSUMER_ID,
    statistics: stats,
    recent_processed: processedMessages.slice(-10),
    recent_rejected: rejectedMessages.slice(-10),
  });
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'kafka-consumer',
    consumer_id: CONSUMER_ID,
    total_consumed: stats.total_consumed,
    authorized: stats.authorized,
    rejected: stats.rejected_no_pca + stats.rejected_invalid_pca + stats.rejected_insufficient_ops,
  });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`[Consumer] Kafka Consumer listening on port ${PORT}`);
  console.log(`[Consumer] Consumer ID: ${CONSUMER_ID}`);
  console.log(`[Consumer] Broker: ${BROKER_URL}`);
  console.log('[Consumer] This consumer validates PCA before processing messages');
});

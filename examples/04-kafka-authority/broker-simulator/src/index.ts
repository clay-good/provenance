/**
 * Kafka Broker Simulator
 *
 * A simplified Kafka broker that demonstrates PIC authority propagation.
 * In a real Kafka deployment, messages would be stored in partitions.
 * This simulator shows the key concept: PCA embedded in message headers.
 *
 * Key concepts:
 * - Messages include X-PIC-PCA header with authority
 * - Producer must have write:kafka:{topic}:* authority
 * - Consumer validates PCA before processing
 * - Authority chain is preserved through the message queue
 */

import express from 'express';

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.BROKER_PORT ?? 9092;

// =============================================================================
// Types
// =============================================================================

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

interface Topic {
  name: string;
  partitions: Map<number, KafkaMessage[]>;
  consumerOffsets: Map<string, Map<number, number>>; // consumerId -> partition -> offset
}

interface ProduceRequest {
  topic: string;
  key: string;
  value: string;
  headers?: Record<string, string>;
  partition?: number;
}

interface ConsumeRequest {
  topic: string;
  consumer_id: string;
  max_messages?: number;
}

// =============================================================================
// In-Memory Broker State
// =============================================================================

const topics = new Map<string, Topic>();

function getOrCreateTopic(name: string): Topic {
  let topic = topics.get(name);
  if (!topic) {
    topic = {
      name,
      partitions: new Map([[0, []], [1, []], [2, []]]), // 3 partitions by default
      consumerOffsets: new Map(),
    };
    topics.set(name, topic);
    console.log(`[Broker] Created topic: ${name}`);
  }
  return topic;
}

function selectPartition(topic: Topic, key: string, partition?: number): number {
  if (partition !== undefined) return partition;
  // Simple hash-based partition selection
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = (hash * 31 + key.charCodeAt(i)) % topic.partitions.size;
  }
  return Math.abs(hash);
}

// =============================================================================
// Broker Server
// =============================================================================

const app = express();
app.use(express.json());

/**
 * POST /produce
 *
 * Produce a message to a topic. The producer should include X-PIC-PCA
 * in the message headers to authorize the write.
 */
app.post('/produce', (req, res) => {
  try {
    const { topic: topicName, key, value, headers, partition } = req.body as ProduceRequest;

    if (!topicName || !key || value === undefined) {
      return res.status(400).json({
        error: 'Missing required fields: topic, key, value',
        code: 'BAD_REQUEST',
      });
    }

    // Check for PCA in headers
    const pca = headers?.['x-pic-pca'];
    if (!pca) {
      console.log(`[Broker] WARNING: Message without PCA header on topic ${topicName}`);
    } else {
      console.log(`[Broker] Message with PCA on topic ${topicName}, key=${key}`);
    }

    const topic = getOrCreateTopic(topicName);
    const selectedPartition = selectPartition(topic, key, partition);
    const partitionMessages = topic.partitions.get(selectedPartition) ?? [];

    const message: KafkaMessage = {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      topic: topicName,
      partition: selectedPartition,
      key,
      value,
      headers: headers ?? {},
      timestamp: Date.now(),
      offset: partitionMessages.length,
    };

    partitionMessages.push(message);
    topic.partitions.set(selectedPartition, partitionMessages);

    console.log(`[Broker] Produced: topic=${topicName}, partition=${selectedPartition}, offset=${message.offset}, key=${key}`);

    return res.json({
      success: true,
      topic: topicName,
      partition: selectedPartition,
      offset: message.offset,
      timestamp: message.timestamp,
      has_pca: !!pca,
    });

  } catch (error) {
    console.error('[Broker] Produce error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

/**
 * POST /consume
 *
 * Consume messages from a topic. Consumer manages its own offset.
 * Returns messages with their PCA headers intact.
 */
app.post('/consume', (req, res) => {
  try {
    const { topic: topicName, consumer_id, max_messages = 10 } = req.body as ConsumeRequest;

    if (!topicName || !consumer_id) {
      return res.status(400).json({
        error: 'Missing required fields: topic, consumer_id',
        code: 'BAD_REQUEST',
      });
    }

    const topic = topics.get(topicName);
    if (!topic) {
      return res.json({ messages: [], topic: topicName });
    }

    // Get or initialize consumer offsets
    let consumerOffsets = topic.consumerOffsets.get(consumer_id);
    if (!consumerOffsets) {
      consumerOffsets = new Map();
      for (const partition of topic.partitions.keys()) {
        consumerOffsets.set(partition, 0);
      }
      topic.consumerOffsets.set(consumer_id, consumerOffsets);
    }

    // Collect messages from all partitions
    const messages: KafkaMessage[] = [];
    for (const [partition, partitionMessages] of topic.partitions) {
      const offset = consumerOffsets.get(partition) ?? 0;
      const newMessages = partitionMessages.slice(offset, offset + max_messages);
      messages.push(...newMessages);
      consumerOffsets.set(partition, offset + newMessages.length);
    }

    // Sort by timestamp
    messages.sort((a, b) => a.timestamp - b.timestamp);
    const result = messages.slice(0, max_messages);

    console.log(`[Broker] Consumed: consumer=${consumer_id}, topic=${topicName}, count=${result.length}`);

    return res.json({
      messages: result,
      topic: topicName,
      consumer_id,
    });

  } catch (error) {
    console.error('[Broker] Consume error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

/**
 * POST /commit
 *
 * Commit consumer offsets (acknowledge message processing).
 */
app.post('/commit', (req, res) => {
  const { topic: topicName, consumer_id, partition, offset } = req.body as {
    topic: string;
    consumer_id: string;
    partition: number;
    offset: number;
  };

  const topic = topics.get(topicName);
  if (!topic) {
    return res.status(404).json({ error: 'Topic not found', code: 'NOT_FOUND' });
  }

  let consumerOffsets = topic.consumerOffsets.get(consumer_id);
  if (!consumerOffsets) {
    consumerOffsets = new Map();
    topic.consumerOffsets.set(consumer_id, consumerOffsets);
  }

  consumerOffsets.set(partition, offset);
  console.log(`[Broker] Committed: consumer=${consumer_id}, topic=${topicName}, partition=${partition}, offset=${offset}`);

  return res.json({ success: true });
});

/**
 * GET /topics
 *
 * List all topics and their message counts.
 */
app.get('/topics', (_req, res) => {
  const topicList = [];
  for (const [name, topic] of topics) {
    let totalMessages = 0;
    for (const messages of topic.partitions.values()) {
      totalMessages += messages.length;
    }
    topicList.push({
      name,
      partitions: topic.partitions.size,
      total_messages: totalMessages,
    });
  }
  return res.json({ topics: topicList });
});

/**
 * GET /topics/:topic/messages
 *
 * Debug endpoint: List all messages in a topic (for demo purposes).
 */
app.get('/topics/:topic/messages', (req, res) => {
  const topicName = req.params.topic;
  const topic = topics.get(topicName);

  if (!topic) {
    return res.status(404).json({ error: 'Topic not found', code: 'NOT_FOUND' });
  }

  const allMessages: KafkaMessage[] = [];
  for (const messages of topic.partitions.values()) {
    allMessages.push(...messages);
  }
  allMessages.sort((a, b) => a.timestamp - b.timestamp);

  return res.json({
    topic: topicName,
    messages: allMessages,
    total: allMessages.length,
  });
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'kafka-broker-simulator',
    topics: topics.size,
  });
});

// =============================================================================
// Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log(`[Broker] Kafka Broker Simulator listening on port ${PORT}`);
  console.log('[Broker] This simulates Kafka for demonstrating PIC authority');
  console.log('[Broker] Messages include X-PIC-PCA header for authority tracking');
});

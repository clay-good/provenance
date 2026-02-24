import { describe, it, expect } from 'vitest';
import { PocBuilder, createPoc, createAndSignPoc } from './poc-builder.js';
import { generateKeyPair, bytesToBase64, base64ToBytes, verifyPoc } from './crypto.js';

describe('PocBuilder', () => {
  const predecessorBytes = new Uint8Array([10, 20, 30, 40]);
  const predecessorB64 = bytesToBase64(predecessorBytes);

  it('builds a basic PoC from Uint8Array predecessor', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .build();

    expect(poc.predecessor).toBe(predecessorB64);
    expect(poc.successor.ops).toEqual(['read:*']);
  });

  it('builds a basic PoC from base64 predecessor', () => {
    const poc = new PocBuilder(predecessorB64)
      .withOps(['read:*'])
      .build();

    expect(poc.predecessor).toBe(predecessorB64);
  });

  it('sets executor binding', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:claims:*'])
      .withExecutor({ service: 'gateway', tool: 'search' })
      .build();

    expect(poc.successor.executor).toEqual({
      service: 'gateway',
      tool: 'search',
    });
  });

  it('adds executor bindings incrementally', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .addExecutorBinding('service', 'agent')
      .addExecutorBinding('task_id', '123')
      .build();

    expect(poc.successor.executor).toEqual({
      service: 'agent',
      task_id: '123',
    });
  });

  it('adds operations incrementally', () => {
    const poc = new PocBuilder(predecessorBytes)
      .addOp('read:claims:*')
      .addOp('write:claims:alice/*')
      .build();

    expect(poc.successor.ops).toEqual([
      'read:claims:*',
      'write:claims:alice/*',
    ]);
  });

  it('sets temporal constraints with expiresIn', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .expiresIn(3600)
      .build();

    expect(poc.successor.constraints?.temporal?.exp).toBeDefined();
    expect(poc.successor.constraints?.temporal?.iat).toBeDefined();
  });

  it('sets full constraints', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .withConstraints({
        temporal: { exp: '2099-01-01T00:00:00Z' },
      })
      .build();

    expect(poc.successor.constraints?.temporal?.exp).toBe('2099-01-01T00:00:00Z');
  });

  it('adds attestation', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .withAttestation('nitro', new Uint8Array([1, 2, 3]), { region: 'us-east-1' })
      .build();

    expect(poc.attestation).toBeDefined();
    expect(poc.attestation!.type).toBe('nitro');
    expect(poc.attestation!.metadata).toEqual({ region: 'us-east-1' });
  });

  it('adds attestation from base64 string', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .withAttestation('custom', 'AQID')
      .build();

    expect(poc.attestation!.data).toBe('AQID');
  });

  it('omits executor when empty', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .build();

    expect(poc.successor.executor).toBeUndefined();
  });

  it('omits attestation when not set', () => {
    const poc = new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .build();

    expect(poc.attestation).toBeUndefined();
  });

  it('signs a PoC', async () => {
    const kp = await generateKeyPair('test');

    const signedPoc = await new PocBuilder(predecessorBytes)
      .withOps(['read:*'])
      .withExecutor({ service: 'test' })
      .sign(kp);

    expect(signedPoc.bytes).toBeInstanceOf(Uint8Array);
    expect(signedPoc.bytes.length).toBeGreaterThan(0);

    // Verify the signed PoC
    const verified = await verifyPoc(signedPoc, kp.publicKey);
    expect(verified.successor.ops).toEqual(['read:*']);
  });
});

describe('createPoc', () => {
  it('creates a PoC with ops', () => {
    const poc = createPoc(
      new Uint8Array([1, 2, 3]),
      ['read:*', 'write:*']
    );

    expect(poc.successor.ops).toEqual(['read:*', 'write:*']);
    expect(poc.successor.executor).toBeUndefined();
  });

  it('creates a PoC with executor', () => {
    const poc = createPoc(
      new Uint8Array([1, 2, 3]),
      ['read:*'],
      { service: 'my-service' }
    );

    expect(poc.successor.executor).toEqual({ service: 'my-service' });
  });
});

describe('createAndSignPoc', () => {
  it('creates and signs a PoC in one step', async () => {
    const kp = await generateKeyPair('test');

    const signedPoc = await createAndSignPoc(
      new Uint8Array([1, 2, 3]),
      ['read:*'],
      kp,
      { service: 'test' }
    );

    expect(signedPoc.bytes).toBeInstanceOf(Uint8Array);

    const verified = await verifyPoc(signedPoc, kp.publicKey);
    expect(verified.successor.ops).toEqual(['read:*']);
  });
});

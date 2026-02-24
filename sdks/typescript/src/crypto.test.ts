import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  importKeyPair,
  getPublicKey,
  signPoc,
  verifyPoc,
  verifyCoseSign1,
  extractKidFromCoseSign1,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
} from './crypto.js';
import type { Poc } from './types.js';

describe('Key Generation', () => {
  it('generates a key pair with correct sizes', async () => {
    const kp = await generateKeyPair('test-key');
    expect(kp.kid).toBe('test-key');
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.privateKey).toHaveLength(64); // seed + public
  });

  it('generates a random kid if not provided', async () => {
    const kp = await generateKeyPair();
    expect(kp.kid).toMatch(/^key-/);
    expect(kp.kid.length).toBeGreaterThan(4);
  });

  it('generates unique key pairs', async () => {
    const kp1 = await generateKeyPair('key-1');
    const kp2 = await generateKeyPair('key-2');
    expect(bytesToHex(kp1.publicKey)).not.toBe(bytesToHex(kp2.publicKey));
  });
});

describe('Key Import', () => {
  it('imports a 32-byte seed', async () => {
    const original = await generateKeyPair('original');
    const seed = original.privateKey.slice(0, 32);

    const imported = await importKeyPair('imported', seed);
    expect(bytesToHex(imported.publicKey)).toBe(bytesToHex(original.publicKey));
  });

  it('imports a 64-byte private key', async () => {
    const original = await generateKeyPair('original');
    const imported = await importKeyPair('imported', original.privateKey);
    expect(bytesToHex(imported.publicKey)).toBe(bytesToHex(original.publicKey));
  });

  it('rejects invalid key lengths', async () => {
    await expect(importKeyPair('bad', new Uint8Array(16))).rejects.toThrow(
      'Invalid private key length'
    );
  });
});

describe('getPublicKey', () => {
  it('returns the public key from a key pair', async () => {
    const kp = await generateKeyPair('test');
    const pk = getPublicKey(kp);
    expect(bytesToHex(pk)).toBe(bytesToHex(kp.publicKey));
  });
});

describe('PoC Signing and Verification', () => {
  const makePoc = (): Poc => ({
    predecessor: bytesToBase64(new Uint8Array([1, 2, 3, 4])),
    successor: {
      ops: ['read:*'],
      executor: { service: 'test' },
    },
  });

  it('signs and verifies a PoC', async () => {
    const kp = await generateKeyPair('sign-key');
    const poc = makePoc();

    const signed = await signPoc(poc, kp);
    expect(signed.bytes).toBeInstanceOf(Uint8Array);
    expect(signed.bytes.length).toBeGreaterThan(0);
    expect(signed.poc).toEqual(poc);

    const verified = await verifyPoc(signed, kp.publicKey);
    expect(verified).toEqual(poc);
  });

  it('verifies from raw bytes', async () => {
    const kp = await generateKeyPair('sign-key');
    const poc = makePoc();

    const signed = await signPoc(poc, kp);
    const verified = await verifyPoc(signed.bytes, kp.publicKey);
    expect(verified).toEqual(poc);
  });

  it('rejects verification with wrong key', async () => {
    const kp1 = await generateKeyPair('key-1');
    const kp2 = await generateKeyPair('key-2');
    const poc = makePoc();

    const signed = await signPoc(poc, kp1);
    await expect(verifyPoc(signed, kp2.publicKey)).rejects.toThrow(
      'signature verification failed'
    );
  });
});

describe('COSE_Sign1', () => {
  it('extracts kid from signed PoC', async () => {
    const kp = await generateKeyPair('my-kid');
    const poc = makePoc();

    const signed = await signPoc(poc, kp);
    const kid = extractKidFromCoseSign1(signed.bytes);
    expect(kid).toBe('my-kid');
  });

  it('returns undefined for invalid bytes', () => {
    const kid = extractKidFromCoseSign1(new Uint8Array([0, 1, 2]));
    expect(kid).toBeUndefined();
  });

  it('verifies COSE_Sign1 and returns payload', async () => {
    const kp = await generateKeyPair('test');
    const poc = makePoc();

    const signed = await signPoc(poc, kp);
    const payload = await verifyCoseSign1(signed.bytes, kp.publicKey);
    expect(payload).toBeInstanceOf(Uint8Array);

    const decoded = JSON.parse(new TextDecoder().decode(payload));
    expect(decoded).toEqual(poc);
  });
});

describe('Hex/Base64 Utilities', () => {
  it('round-trips hex encoding', () => {
    const original = new Uint8Array([0, 127, 255, 1, 16]);
    const hex = bytesToHex(original);
    const restored = hexToBytes(hex);
    expect(bytesToHex(restored)).toBe(bytesToHex(original));
  });

  it('round-trips base64 encoding', () => {
    const original = new Uint8Array([10, 20, 30, 40, 50]);
    const b64 = bytesToBase64(original);
    const restored = base64ToBytes(b64);
    expect(bytesToHex(restored)).toBe(bytesToHex(original));
  });

  it('handles empty arrays', () => {
    expect(bytesToHex(new Uint8Array([]))).toBe('');
    expect(bytesToBase64(new Uint8Array([]))).toBe('');
    expect(hexToBytes('')).toEqual(new Uint8Array([]));
    expect(base64ToBytes('')).toEqual(new Uint8Array([]));
  });
});

// Helper for makePoc outside describe blocks
function makePoc(): Poc {
  return {
    predecessor: bytesToBase64(new Uint8Array([1, 2, 3, 4])),
    successor: {
      ops: ['read:*'],
      executor: { service: 'test' },
    },
  };
}

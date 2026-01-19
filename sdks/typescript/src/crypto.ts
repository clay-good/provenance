/**
 * Cryptographic utilities for PIC
 *
 * Provides Ed25519 signing and COSE_Sign1 encoding for PCAs and PoCs.
 * Uses @noble/ed25519 for cryptographic operations and cborg for CBOR encoding.
 */

import * as ed from '@noble/ed25519';
import { encode, decode, Token, Type } from 'cborg';
import { randomBytes } from 'crypto';
import type { KeyPair, Poc, SignedPoc } from './types.js';

// Configure ed25519 to use the async hash function
// This is required for Node.js environments
const sha512 = async (message: Uint8Array): Promise<Uint8Array> => {
  const { createHash } = await import('crypto');
  const hash = createHash('sha512');
  hash.update(message);
  return new Uint8Array(hash.digest());
};

// Set the hash function globally
ed.etc.sha512Sync = undefined; // Clear sync version
ed.etc.sha512Async = sha512;

// =============================================================================
// Key Generation and Management
// =============================================================================

/**
 * Generate a new Ed25519 key pair
 *
 * @param kid - Key ID to assign (or generates a random one)
 * @returns A new KeyPair
 */
export async function generateKeyPair(kid?: string): Promise<KeyPair> {
  // Generate random 32-byte seed
  const seed = randomBytes(32);
  const privateKey = seed;
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  return {
    kid: kid ?? generateKid(),
    privateKey: new Uint8Array([...privateKey, ...publicKey]), // 64 bytes: seed + public
    publicKey: new Uint8Array(publicKey),
  };
}

/**
 * Generate a random key ID
 */
function generateKid(): string {
  const bytes = randomBytes(16);
  return `key-${Buffer.from(bytes).toString('hex').slice(0, 16)}`;
}

/**
 * Import a key pair from raw bytes
 *
 * @param kid - Key ID
 * @param privateKeyBytes - Private key bytes (32 or 64 bytes)
 * @returns KeyPair
 */
export async function importKeyPair(
  kid: string,
  privateKeyBytes: Uint8Array
): Promise<KeyPair> {
  // Ed25519 private keys can be 32 bytes (seed) or 64 bytes (seed + public)
  let seed: Uint8Array;
  if (privateKeyBytes.length === 32) {
    seed = privateKeyBytes;
  } else if (privateKeyBytes.length === 64) {
    seed = privateKeyBytes.slice(0, 32);
  } else {
    throw new Error(
      `Invalid private key length: ${privateKeyBytes.length}, expected 32 or 64`
    );
  }

  const publicKey = await ed.getPublicKeyAsync(seed);

  return {
    kid,
    privateKey: new Uint8Array([...seed, ...publicKey]),
    publicKey: new Uint8Array(publicKey),
  };
}

/**
 * Get the public key from a key pair
 */
export function getPublicKey(keyPair: KeyPair): Uint8Array {
  return keyPair.publicKey;
}

// =============================================================================
// COSE_Sign1 Encoding
// =============================================================================

/**
 * COSE Header Parameters (subset we use)
 */
const COSE_HEADER_ALG = 1; // Algorithm
const COSE_HEADER_KID = 4; // Key ID
const COSE_ALG_EDDSA = -8; // EdDSA algorithm identifier
const COSE_SIGN1_TAG = 18; // CBOR tag for COSE_Sign1

/**
 * Create a COSE_Sign1 structure
 *
 * COSE_Sign1 = [
 *   protected: bstr,   // CBOR-encoded protected headers
 *   unprotected: {},   // Unprotected headers (empty)
 *   payload: bstr,     // The payload
 *   signature: bstr    // The signature
 * ]
 */
async function createCoseSign1(
  payload: Uint8Array,
  keyPair: KeyPair
): Promise<Uint8Array> {
  // Protected headers: { 1: -8 (EdDSA), 4: kid }
  // Must use Map for CBOR integer keys (cborg encodes object keys as strings)
  const protectedHeaders = new Map<number, unknown>();
  protectedHeaders.set(COSE_HEADER_ALG, COSE_ALG_EDDSA);
  protectedHeaders.set(COSE_HEADER_KID, new TextEncoder().encode(keyPair.kid));

  // Encode protected headers as CBOR
  const protectedBytes = encode(protectedHeaders);

  // Create Sig_structure for signing:
  // Sig_structure = [
  //   context: "Signature1",
  //   body_protected: bstr,
  //   external_aad: bstr (empty),
  //   payload: bstr
  // ]
  const sigStructure = [
    'Signature1',
    protectedBytes,
    new Uint8Array(0), // external_aad
    payload,
  ];

  // Encode the structure to sign
  const toSign = encode(sigStructure);

  // Sign with Ed25519
  const seed = keyPair.privateKey.slice(0, 32);
  const signature = await ed.signAsync(toSign, seed);

  // Build COSE_Sign1 structure as array
  const coseSign1Array = [
    protectedBytes,
    {}, // unprotected headers (empty map)
    payload,
    signature,
  ];

  // Encode the array (untagged - coset library expects untagged COSE_Sign1)
  return encode(coseSign1Array);
}

/**
 * Verify a COSE_Sign1 structure and extract the payload
 *
 * @param coseSign1Bytes - The COSE_Sign1 encoded bytes
 * @param publicKey - The public key to verify against
 * @returns The payload bytes if verification succeeds
 * @throws Error if verification fails
 */
export async function verifyCoseSign1(
  coseSign1Bytes: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  // Decode the COSE_Sign1 structure
  // Use tag decoder to handle CBOR tag 18
  let tagValue: number | undefined;
  const decoded = decode(coseSign1Bytes, {
    tags: {
      [COSE_SIGN1_TAG]: (value: unknown) => {
        tagValue = COSE_SIGN1_TAG;
        return value;
      },
    },
  } as { tags: Record<number, (value: unknown) => unknown> });

  // Handle tagged or untagged COSE_Sign1
  let coseArray: unknown[];
  if (Array.isArray(decoded)) {
    coseArray = decoded;
  } else {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  if (coseArray.length !== 4) {
    throw new Error(`Invalid COSE_Sign1 array length: ${coseArray.length}`);
  }

  const [protectedBytes, , payload, signature] = coseArray as [
    Uint8Array,
    unknown,
    Uint8Array,
    Uint8Array
  ];

  // Recreate Sig_structure
  const sigStructure = [
    'Signature1',
    protectedBytes,
    new Uint8Array(0),
    payload,
  ];
  const toVerify = encode(sigStructure);

  // Verify signature
  const valid = await ed.verifyAsync(signature, toVerify, publicKey);
  if (!valid) {
    throw new Error('COSE_Sign1 signature verification failed');
  }

  return payload;
}

/**
 * Extract the key ID from a COSE_Sign1 structure without verifying
 *
 * @param coseSign1Bytes - The COSE_Sign1 encoded bytes
 * @returns The key ID if present
 */
export function extractKidFromCoseSign1(
  coseSign1Bytes: Uint8Array
): string | undefined {
  try {
    const decoded = decode(coseSign1Bytes, {
      tags: {
        [COSE_SIGN1_TAG]: (value: unknown) => value,
      },
    } as { tags: Record<number, (value: unknown) => unknown> });

    let coseArray: unknown[];
    if (Array.isArray(decoded)) {
      coseArray = decoded;
    } else {
      return undefined;
    }

    const protectedBytes = coseArray[0] as Uint8Array;
    // Use useMaps: true to handle CBOR maps with integer keys
    const protectedHeaders = decode(protectedBytes, { useMaps: true }) as Map<number, unknown>;

    const kidBytes = protectedHeaders.get(COSE_HEADER_KID);
    if (kidBytes instanceof Uint8Array) {
      return new TextDecoder().decode(kidBytes);
    }

    return undefined;
  } catch {
    return undefined;
  }
}

// =============================================================================
// PoC Signing
// =============================================================================

/**
 * Sign a PoC and create a SignedPoc
 *
 * @param poc - The PoC to sign
 * @param keyPair - The key pair to sign with
 * @returns SignedPoc containing the COSE_Sign1 encoded bytes
 */
export async function signPoc(poc: Poc, keyPair: KeyPair): Promise<SignedPoc> {
  // Encode PoC to JSON (Rust backend expects JSON payload inside COSE_Sign1)
  const pocJson = JSON.stringify(poc);
  const pocBytes = new TextEncoder().encode(pocJson);

  // Create COSE_Sign1
  const signedBytes = await createCoseSign1(pocBytes, keyPair);

  return {
    bytes: signedBytes,
    poc,
  };
}

/**
 * Verify a SignedPoc and extract the PoC
 *
 * @param signedPoc - The signed PoC (bytes or SignedPoc object)
 * @param publicKey - The public key to verify against
 * @returns The verified PoC
 * @throws Error if verification fails
 */
export async function verifyPoc(
  signedPoc: SignedPoc | Uint8Array,
  publicKey: Uint8Array
): Promise<Poc> {
  const bytes = signedPoc instanceof Uint8Array ? signedPoc : signedPoc.bytes;
  const payload = await verifyCoseSign1(bytes, publicKey);
  // Decode JSON payload (Rust backend encodes PoC as JSON inside COSE_Sign1)
  const pocJson = new TextDecoder().decode(payload);
  return JSON.parse(pocJson) as Poc;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Convert bytes to base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Convert base64 string to bytes
 */
export function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

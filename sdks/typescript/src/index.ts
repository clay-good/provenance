/**
 * @provenance/sdk - TypeScript SDK for PIC Trust Plane
 *
 * This SDK provides tools for working with the PIC (Provenance Identity Continuity)
 * Trust Plane, which eliminates confused deputy attacks by construction through
 * cryptographic authority chains.
 *
 * ## Core Concepts
 *
 * - **PCA (Proof of Causal Authority)**: Authority state at each execution hop
 * - **PoC (Proof of Continuity)**: Request to delegate authority to the next hop
 * - **Trust Plane**: The service that validates PoCs and issues successor PCAs
 *
 * ## The Three PIC Invariants
 *
 * 1. **PROVENANCE**: p_0 (origin principal) is IMMUTABLE throughout the chain
 * 2. **IDENTITY**: ops can only SHRINK (ops_{i+1} ⊆ ops_i)
 * 3. **CONTINUITY**: Cryptographic chain linking each hop
 *
 * ## Quick Start
 *
 * ```typescript
 * import {
 *   TrustPlaneClient,
 *   PocBuilder,
 *   generateKeyPair,
 * } from '@provenance/sdk';
 *
 * // Create a client
 * const client = new TrustPlaneClient('http://localhost:8080');
 *
 * // Generate a key pair for this service
 * const keyPair = await generateKeyPair('my-service-key');
 *
 * // Register with Trust Plane
 * await client.registerExecutorKey(keyPair.kid, keyPair.publicKey);
 *
 * // Issue initial PCA (federation entry)
 * const pca0 = await client.issuePca({
 *   credential: 'my-jwt-token',
 *   credential_type: 'jwt',
 *   ops: ['read:*', 'write:claims/*'],
 * });
 *
 * // Create a PoC to request authority delegation
 * const signedPoc = await new PocBuilder(pca0.pca)
 *   .withOps(['read:claims/123'])
 *   .withExecutor({ service: 'my-service' })
 *   .sign(keyPair);
 *
 * // Get successor PCA
 * const pca1 = await client.processPoc(signedPoc);
 * console.log(`Authority delegated: hop ${pca1.hop}, ops: ${pca1.ops}`);
 * ```
 *
 * @module @provenance/sdk
 */

// =============================================================================
// Types
// =============================================================================

export type {
  // Principal types
  PrincipalType,
  PrincipalIdentifier,
  // Constraint types
  TemporalConstraints,
  EnvironmentConstraints,
  BudgetConstraints,
  Constraints,
  // PCA types
  ExecutorBinding,
  Provenance,
  Pca,
  // PoC types
  SuccessorRequest,
  AttestationType,
  Attestation,
  Poc,
  // API types
  IssuePcaRequest,
  IssuePcaResponse,
  ProcessPocRequest,
  ProcessPocResponse,
  RegisterKeyRequest,
  ListKeysResponse,
  // Crypto types
  KeyPair,
  SignedPca,
  SignedPoc,
  // Error types
  TrustPlaneError,
  PicErrorCode,
  // Context types
  PicContext,
} from './types.js';

export { isTrustPlaneError, isPca0 } from './types.js';

// =============================================================================
// Client
// =============================================================================

export {
  TrustPlaneClient,
  TrustPlaneApiError,
  base64ToUint8Array,
  type TrustPlaneClientOptions,
} from './client.js';

// =============================================================================
// PoC Builder
// =============================================================================

export { PocBuilder, createPoc, createAndSignPoc } from './poc-builder.js';

// =============================================================================
// Crypto
// =============================================================================

export {
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

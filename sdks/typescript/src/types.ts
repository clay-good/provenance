/**
 * TypeScript types for the PIC Trust Plane SDK
 *
 * These types mirror the Rust types in provenance-core and are used
 * for serialization/deserialization with the Trust Plane API.
 */

// =============================================================================
// Principal Types
// =============================================================================

/**
 * Types of principal identifiers
 */
export type PrincipalType =
  | 'oidc'
  | 'spiffe'
  | 'did'
  | 'x509'
  | 'apikey'
  | 'custom';

/**
 * Principal identifier representing the origin of authority
 */
export interface PrincipalIdentifier {
  /** Type of principal */
  type: PrincipalType;
  /** Principal value (e.g., "https://idp.example/users/alice") */
  value: string;
  /** Optional additional claims */
  claims?: Record<string, unknown>;
}

// =============================================================================
// Constraint Types
// =============================================================================

/**
 * Temporal constraints for PCA validity (RFC 3339 timestamps)
 */
export interface TemporalConstraints {
  /** Issued at */
  iat?: string;
  /** Expiration */
  exp?: string;
  /** Not before */
  nbf?: string;
}

/**
 * Environment constraints
 */
export interface EnvironmentConstraints {
  /** Allowed regions */
  regions?: string[];
  /** Allowed IP ranges */
  ip_ranges?: string[];
  /** Required TEE type */
  tee_type?: string;
}

/**
 * Budget constraints
 */
export interface BudgetConstraints {
  /** Maximum API calls */
  max_calls?: number;
  /** Maximum cost in currency units */
  max_cost?: number;
  /** Currency for cost */
  currency?: string;
}

/**
 * All constraints that can be applied to a PCA
 */
export interface Constraints {
  /** Temporal constraints */
  temporal?: TemporalConstraints;
  /** Environment constraints */
  environment?: EnvironmentConstraints;
  /** Budget constraints */
  budget?: BudgetConstraints;
}

// =============================================================================
// PCA Types
// =============================================================================

/**
 * Executor binding - metadata about who is executing at this hop
 *
 * Common keys:
 * - "service": Service name
 * - "tool": For AI agents, the tool being invoked
 * - "agent_id": Unique agent identifier
 * - "task_id": The task/request ID
 * - "federation": Federation/realm
 */
export type ExecutorBinding = Record<string, string>;

/**
 * Provenance - cryptographic link to predecessor PCA
 *
 * Establishes the CONTINUITY invariant by recording:
 * - Who signed the predecessor PCA (CAT key)
 * - The signature on the predecessor
 * - Who created this PoC (executor key)
 * - The signature on the PoC
 */
export interface Provenance {
  /** Key ID of the Trust Plane (CAT) that signed the predecessor PCA */
  cat_kid: string;
  /** Base64-encoded signature bytes from the predecessor PCA */
  cat_sig: string;
  /** Key ID of the executor that signed the PoC */
  executor_kid: string;
  /** Base64-encoded signature bytes from the PoC */
  executor_sig: string;
}

/**
 * Proof of Causal Authority - authority state at execution hop i
 *
 * The PCA is the core credential in the PIC model. It carries:
 * - The immutable origin principal (p_0) who initiated the request
 * - The allowed operations at this hop (can only shrink from predecessor)
 * - Provenance linking to the predecessor PCA (for hop > 0)
 * - Optional constraints (temporal, budget, etc.)
 */
export interface Pca {
  /** Hop number in the causal chain (0 for PCA_0) */
  hop: number;
  /** Origin principal - IMMUTABLE throughout the chain */
  p_0: PrincipalIdentifier;
  /** Allowed operations - can only SHRINK across hops */
  ops: string[];
  /** Executor binding - key-value metadata */
  executor: ExecutorBinding;
  /** Provenance linking to predecessor (undefined for PCA_0) */
  provenance?: Provenance;
  /** Constraints (temporal, budget, environment) */
  constraints?: Constraints;
}

// =============================================================================
// PoC Types
// =============================================================================

/**
 * Request for a successor PCA
 *
 * Specifies what authority the executor wants in the successor.
 * The Trust Plane will validate that:
 * - ops ⊆ predecessor.ops (monotonicity)
 * - constraints do not exceed predecessor constraints
 */
export interface SuccessorRequest {
  /** Requested operations - MUST be subset of predecessor */
  ops: string[];
  /** Executor binding for the successor PCA */
  executor?: ExecutorBinding;
  /** Requested constraints (cannot exceed predecessor) */
  constraints?: Constraints;
}

/**
 * Attestation types
 */
export type AttestationType =
  | 'sgx'
  | 'sev'
  | 'trustzone'
  | 'nitro'
  | 'custom';

/**
 * Additional attestation that can accompany a PoC
 */
export interface Attestation {
  /** Type of attestation */
  type: AttestationType;
  /** Base64-encoded attestation data */
  data: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Proof of Continuity - request for a successor PCA
 *
 * The PoC establishes the causal link between hops by containing:
 * 1. The predecessor PCA (signed, proving current authority)
 * 2. The successor request (what the executor wants)
 * 3. Optional attestation (additional proof)
 */
export interface Poc {
  /** Base64-encoded signed predecessor PCA bytes (COSE_Sign1 encoded) */
  predecessor: string;
  /** What the executor is requesting for the successor PCA */
  successor: SuccessorRequest;
  /** Optional attestation */
  attestation?: Attestation;
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/**
 * Request to issue a PCA_0 (federation entry)
 */
export interface IssuePcaRequest {
  /** External credential (JWT, API key, etc.) */
  credential: string;
  /** Type of credential */
  credential_type: string;
  /** Requested operations */
  ops: string[];
  /** Executor binding metadata */
  executor_binding?: ExecutorBinding;
}

/**
 * Response from PCA_0 issuance
 */
export interface IssuePcaResponse {
  /** Base64-encoded signed PCA */
  pca: string;
  /** Hop number (always 0 for PCA_0) */
  hop: number;
  /** Origin principal value */
  p_0: string;
  /** Granted operations */
  ops: string[];
  /** Expiration (RFC 3339, if any) */
  exp?: string;
}

/**
 * Request to process a PoC
 */
export interface ProcessPocRequest {
  /** Base64-encoded signed PoC */
  poc: string;
}

/**
 * Response from PoC processing
 */
export interface ProcessPocResponse {
  /** Base64-encoded signed successor PCA */
  pca: string;
  /** Hop number */
  hop: number;
  /** Origin principal value (unchanged from predecessor) */
  p_0: string;
  /** Granted operations */
  ops: string[];
  /** Expiration (RFC 3339, if any) */
  exp?: string;
}

/**
 * Request to register an executor public key
 */
export interface RegisterKeyRequest {
  /** Key ID */
  kid: string;
  /** Base64-encoded Ed25519 public key (32 bytes) */
  public_key: string;
}

/**
 * Response listing registered executor key IDs
 */
export interface ListKeysResponse {
  /** List of registered key IDs */
  keys: string[];
}

// =============================================================================
// Crypto Types
// =============================================================================

/**
 * Key pair for Ed25519 signing
 */
export interface KeyPair {
  /** Key ID */
  kid: string;
  /** Private key bytes (64 bytes for Ed25519) */
  privateKey: Uint8Array;
  /** Public key bytes (32 bytes) */
  publicKey: Uint8Array;
}

/**
 * Signed PCA (COSE_Sign1 wrapped)
 */
export interface SignedPca {
  /** Raw COSE_Sign1 bytes */
  bytes: Uint8Array;
  /** Decoded PCA (if available) */
  pca?: Pca;
}

/**
 * Signed PoC (COSE_Sign1 wrapped)
 */
export interface SignedPoc {
  /** Raw COSE_Sign1 bytes */
  bytes: Uint8Array;
  /** Decoded PoC (if available) */
  poc?: Poc;
}

// =============================================================================
// Error Types
// =============================================================================

/**
 * Trust Plane API error response
 */
export interface TrustPlaneError {
  /** Error code */
  code: string;
  /** Human-readable error message */
  message: string;
  /** Additional error details */
  details?: Record<string, unknown>;
}

/**
 * PIC-specific errors that can occur during authority chain operations
 */
export type PicErrorCode =
  | 'MONOTONICITY_VIOLATION'  // ops_{i+1} ⊄ ops_i
  | 'UNKNOWN_EXECUTOR'        // Executor key not registered
  | 'INVALID_SIGNATURE'       // Signature verification failed
  | 'PCA_EXPIRED'             // PCA temporal constraint violated
  | 'INVALID_FORMAT'          // Malformed request
  | 'FORBIDDEN'               // Not authorized for requested operation
  | 'INTERNAL_ERROR';         // Server error

// =============================================================================
// Request Context Types (for middleware)
// =============================================================================

/**
 * PIC context attached to requests by middleware
 */
export interface PicContext {
  /** Current PCA (base64-encoded signed) */
  pca: string;
  /** Origin principal value */
  p_0: string;
  /** Current operations */
  ops: string[];
  /** Current hop number */
  hop: number;
  /** Full decoded PCA (if available) */
  decoded?: Pca;
}

// =============================================================================
// Helper Type Guards
// =============================================================================

/**
 * Type guard to check if an error is a TrustPlaneError
 */
export function isTrustPlaneError(error: unknown): error is TrustPlaneError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    'message' in error &&
    typeof (error as TrustPlaneError).code === 'string' &&
    typeof (error as TrustPlaneError).message === 'string'
  );
}

/**
 * Type guard to check if this is a PCA_0
 */
export function isPca0(pca: Pca): boolean {
  return pca.hop === 0 && pca.provenance === undefined;
}

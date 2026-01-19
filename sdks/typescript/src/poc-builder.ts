/**
 * PoC Builder
 *
 * Fluent builder for creating Proof of Continuity (PoC) requests.
 */

import type {
  Poc,
  SuccessorRequest,
  ExecutorBinding,
  Constraints,
  TemporalConstraints,
  Attestation,
  AttestationType,
  KeyPair,
  SignedPoc,
} from './types.js';
import { signPoc, bytesToBase64, base64ToBytes } from './crypto.js';

/**
 * Builder for constructing PoC (Proof of Continuity) requests
 *
 * @example
 * ```typescript
 * // Create a PoC to request a subset of operations
 * const poc = new PocBuilder(predecessorPcaBytes)
 *   .withOps(['read:claims:alice/*'])
 *   .withExecutor({ service: 'claims-service', tool: 'get-claim' })
 *   .build();
 *
 * // Sign the PoC
 * const signedPoc = await poc.sign(keyPair);
 *
 * // Submit to Trust Plane
 * const response = await client.processPoc(signedPoc);
 * ```
 */
export class PocBuilder {
  private predecessorPca: Uint8Array;
  private ops: string[] = [];
  private executor: ExecutorBinding = {};
  private constraints?: Constraints;
  private attestation?: Attestation;

  /**
   * Create a new PocBuilder
   *
   * @param predecessorPca - The predecessor PCA (base64 string or Uint8Array)
   */
  constructor(predecessorPca: Uint8Array | string) {
    if (typeof predecessorPca === 'string') {
      this.predecessorPca = base64ToBytes(predecessorPca);
    } else {
      this.predecessorPca = predecessorPca;
    }
  }

  /**
   * Set the requested operations
   *
   * The operations MUST be a subset of the predecessor's operations.
   * If not, the Trust Plane will reject the PoC with a monotonicity violation.
   *
   * @param ops - Operations to request (e.g., ['read:claims:*', 'write:claims:alice/*'])
   */
  withOps(ops: string[]): this {
    this.ops = [...ops];
    return this;
  }

  /**
   * Add an operation to the requested set
   *
   * @param op - Operation to add
   */
  addOp(op: string): this {
    this.ops.push(op);
    return this;
  }

  /**
   * Set the executor binding metadata
   *
   * Common keys:
   * - "service": Service name
   * - "tool": For AI agents, the tool being invoked
   * - "agent_id": Agent identifier
   * - "task_id": Task/request ID
   *
   * @param executor - Executor binding key-value pairs
   */
  withExecutor(executor: ExecutorBinding): this {
    this.executor = { ...executor };
    return this;
  }

  /**
   * Add a key-value pair to executor binding
   *
   * @param key - The key
   * @param value - The value
   */
  addExecutorBinding(key: string, value: string): this {
    this.executor[key] = value;
    return this;
  }

  /**
   * Set temporal constraints
   *
   * The expiration cannot exceed the predecessor's expiration.
   *
   * @param temporal - Temporal constraints
   */
  withTemporalConstraints(temporal: TemporalConstraints): this {
    this.constraints = {
      ...this.constraints,
      temporal,
    };
    return this;
  }

  /**
   * Set expiration relative to now
   *
   * @param seconds - Seconds until expiration
   */
  expiresIn(seconds: number): this {
    const exp = new Date(Date.now() + seconds * 1000).toISOString();
    return this.withTemporalConstraints({
      ...this.constraints?.temporal,
      iat: new Date().toISOString(),
      exp,
    });
  }

  /**
   * Set all constraints
   *
   * @param constraints - Full constraints object
   */
  withConstraints(constraints: Constraints): this {
    this.constraints = { ...constraints };
    return this;
  }

  /**
   * Add an attestation
   *
   * @param type - Attestation type
   * @param data - Attestation data (bytes or base64)
   * @param metadata - Optional metadata
   */
  withAttestation(
    type: AttestationType,
    data: Uint8Array | string,
    metadata?: Record<string, unknown>
  ): this {
    this.attestation = {
      type,
      data: typeof data === 'string' ? data : bytesToBase64(data),
      metadata,
    };
    return this;
  }

  /**
   * Build the PoC object
   *
   * @returns The constructed PoC
   */
  build(): Poc {
    const successor: SuccessorRequest = {
      ops: this.ops,
    };

    if (Object.keys(this.executor).length > 0) {
      successor.executor = this.executor;
    }

    if (this.constraints) {
      successor.constraints = this.constraints;
    }

    const poc: Poc = {
      predecessor: bytesToBase64(this.predecessorPca),
      successor,
    };

    if (this.attestation) {
      poc.attestation = this.attestation;
    }

    return poc;
  }

  /**
   * Build and sign the PoC
   *
   * @param keyPair - The key pair to sign with
   * @returns SignedPoc containing the COSE_Sign1 encoded bytes
   */
  async sign(keyPair: KeyPair): Promise<SignedPoc> {
    const poc = this.build();
    return signPoc(poc, keyPair);
  }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Create a simple PoC for requesting a subset of operations
 *
 * @param predecessorPca - The predecessor PCA
 * @param ops - Operations to request
 * @param executor - Optional executor binding
 * @returns The PoC object
 */
export function createPoc(
  predecessorPca: Uint8Array | string,
  ops: string[],
  executor?: ExecutorBinding
): Poc {
  const builder = new PocBuilder(predecessorPca).withOps(ops);
  if (executor) {
    builder.withExecutor(executor);
  }
  return builder.build();
}

/**
 * Create and sign a PoC in one step
 *
 * @param predecessorPca - The predecessor PCA
 * @param ops - Operations to request
 * @param keyPair - Key pair to sign with
 * @param executor - Optional executor binding
 * @returns The signed PoC
 */
export async function createAndSignPoc(
  predecessorPca: Uint8Array | string,
  ops: string[],
  keyPair: KeyPair,
  executor?: ExecutorBinding
): Promise<SignedPoc> {
  const builder = new PocBuilder(predecessorPca).withOps(ops);
  if (executor) {
    builder.withExecutor(executor);
  }
  return builder.sign(keyPair);
}

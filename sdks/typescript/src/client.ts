/**
 * Trust Plane Client
 *
 * HTTP client for interacting with the Trust Plane API.
 */

import type {
  IssuePcaRequest,
  IssuePcaResponse,
  ProcessPocRequest,
  ProcessPocResponse,
  RegisterKeyRequest,
  ListKeysResponse,
  TrustPlaneError,
  SignedPoc,
} from './types.js';

/**
 * Configuration options for the Trust Plane client
 */
export interface TrustPlaneClientOptions {
  /** Base URL of the Trust Plane server */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers to include in all requests */
  headers?: Record<string, string>;
  /** Custom fetch implementation (for testing or custom environments) */
  fetch?: typeof globalThis.fetch;
}

/**
 * Error thrown when Trust Plane API returns an error response
 */
export class TrustPlaneApiError extends Error {
  /** HTTP status code */
  readonly status: number;
  /** Error code from Trust Plane */
  readonly code: string;
  /** Error details */
  readonly details?: Record<string, unknown>;

  constructor(status: number, error: TrustPlaneError) {
    super(error.message);
    this.name = 'TrustPlaneApiError';
    this.status = status;
    this.code = error.code;
    this.details = error.details;
  }
}

/**
 * Trust Plane client for interacting with the Trust Plane API
 *
 * @example
 * ```typescript
 * const client = new TrustPlaneClient({
 *   baseUrl: 'http://localhost:8080',
 * });
 *
 * // Issue a PCA_0
 * const response = await client.issuePca({
 *   credential: 'mock:alice',
 *   credential_type: 'mock',
 *   ops: ['read:*'],
 *   executor_binding: { service: 'my-service' },
 * });
 *
 * console.log(`Issued PCA_0 for ${response.p_0}`);
 * ```
 */
export class TrustPlaneClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly headers: Record<string, string>;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(options: TrustPlaneClientOptions | string) {
    if (typeof options === 'string') {
      this.baseUrl = options.replace(/\/$/, ''); // Remove trailing slash
      this.timeout = 30000;
      this.headers = {};
      this.fetchFn = globalThis.fetch;
    } else {
      this.baseUrl = options.baseUrl.replace(/\/$/, '');
      this.timeout = options.timeout ?? 30000;
      this.headers = options.headers ?? {};
      this.fetchFn = options.fetch ?? globalThis.fetch;
    }
  }

  /**
   * Issue a PCA_0 (federation entry)
   *
   * This is the entry point for getting initial authority. It validates
   * the external credential and issues a PCA_0 with the granted operations.
   *
   * @param request - The issuance request
   * @returns The issued PCA_0 response
   * @throws {TrustPlaneApiError} If the request fails
   */
  async issuePca(request: IssuePcaRequest): Promise<IssuePcaResponse> {
    return this.post<IssuePcaRequest, IssuePcaResponse>(
      '/v1/pca/issue',
      request
    );
  }

  /**
   * Process a PoC and get a successor PCA
   *
   * This is the core authority delegation endpoint. It validates the PoC,
   * enforces monotonicity, and issues a successor PCA.
   *
   * @param signedPoc - The signed PoC (either raw bytes or SignedPoc object)
   * @returns The successor PCA response
   * @throws {TrustPlaneApiError} If monotonicity is violated or other errors
   */
  async processPoc(
    signedPoc: SignedPoc | Uint8Array | string
  ): Promise<ProcessPocResponse> {
    let pocBase64: string;

    if (typeof signedPoc === 'string') {
      // Already base64-encoded
      pocBase64 = signedPoc;
    } else if (signedPoc instanceof Uint8Array) {
      // Raw bytes - encode to base64
      pocBase64 = uint8ArrayToBase64(signedPoc);
    } else {
      // SignedPoc object
      pocBase64 = uint8ArrayToBase64(signedPoc.bytes);
    }

    const request: ProcessPocRequest = { poc: pocBase64 };
    return this.post<ProcessPocRequest, ProcessPocResponse>(
      '/v1/poc/process',
      request
    );
  }

  /**
   * Register an executor public key
   *
   * Executors must register their public keys before they can submit PoCs.
   *
   * @param kid - Key ID
   * @param publicKey - Ed25519 public key (32 bytes)
   */
  async registerExecutorKey(
    kid: string,
    publicKey: Uint8Array
  ): Promise<void> {
    const request: RegisterKeyRequest = {
      kid,
      public_key: uint8ArrayToBase64(publicKey),
    };
    await this.post<RegisterKeyRequest, void>('/v1/keys/executor', request);
  }

  /**
   * List registered executor key IDs
   *
   * @returns List of registered key IDs
   */
  async listExecutorKeys(): Promise<string[]> {
    const response = await this.get<ListKeysResponse>('/v1/keys/executor');
    return response.keys;
  }

  /**
   * Check if the Trust Plane is healthy
   *
   * @returns true if healthy
   */
  async isHealthy(): Promise<boolean> {
    try {
      const response = await this.fetchFn(`${this.baseUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get readiness information
   *
   * @returns Readiness info including CAT key ID
   */
  async getReadyInfo(): Promise<{ status: string; cat_kid: string }> {
    return this.get<{ status: string; cat_kid: string }>('/ready');
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  private async post<TReq, TRes>(path: string, body: TReq): Promise<TRes> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeout),
    });

    return this.handleResponse<TRes>(response);
  }

  private async get<TRes>(path: string): Promise<TRes> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: this.headers,
      signal: AbortSignal.timeout(this.timeout),
    });

    return this.handleResponse<TRes>(response);
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      let error: TrustPlaneError;
      try {
        const jsonError = (await response.json()) as TrustPlaneError;
        error = jsonError;
      } catch {
        error = {
          code: 'UNKNOWN_ERROR',
          message: `HTTP ${response.status}: ${response.statusText}`,
        };
      }
      throw new TrustPlaneApiError(response.status, error);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return (await response.json()) as T;
  }
}

// =============================================================================
// Utility functions
// =============================================================================

/**
 * Convert Uint8Array to base64 string
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Use Buffer in Node.js, btoa in browser
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  // Browser environment
  const binary = String.fromCharCode(...bytes);
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  // Use Buffer in Node.js, atob in browser
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  // Browser environment
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

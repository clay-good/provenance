/**
 * Express Middleware for PIC Authority Chain
 *
 * This middleware automatically handles PCA propagation through Express services:
 * 1. Extracts the incoming PCA from request headers
 * 2. Builds a PoC requesting authority for this hop
 * 3. Submits to Trust Plane for successor PCA
 * 4. Attaches authority info to the request for downstream use
 * 5. Rejects if monotonicity is violated
 */

import type { Request, Response, NextFunction } from 'express';
import type {
  KeyPair,
  PicContext,
  ExecutorBinding,
  ProcessPocResponse,
} from '../types.js';
import { TrustPlaneClient, TrustPlaneApiError } from '../client.js';
import { PocBuilder } from '../poc-builder.js';

// Extend Express Request to include PIC context
declare global {
  namespace Express {
    interface Request {
      /** PIC authority context for this request */
      pic?: PicContext;
    }
  }
}

/**
 * Configuration options for PIC middleware
 */
export interface PicMiddlewareOptions {
  /** URL of the Trust Plane server */
  trustPlaneUrl: string;

  /** Key pair for signing PoCs */
  keyPair: KeyPair;

  /**
   * Function to extract requested operations from the request.
   * If not provided, defaults to requesting all ops from predecessor ('*').
   *
   * @example
   * ```typescript
   * extractOps: (req) => {
   *   // Map HTTP method to operation
   *   const action = req.method === 'GET' ? 'read' : 'write';
   *   const resource = req.path.replace(/\//g, ':');
   *   return [`${action}${resource}`];
   * }
   * ```
   */
  extractOps?: (req: Request) => string[];

  /**
   * Function to build executor binding from request.
   * If not provided, uses a default binding.
   */
  buildExecutor?: (req: Request) => ExecutorBinding;

  /** Service name for executor binding */
  serviceName?: string;

  /**
   * Header name for incoming PCA (default: 'x-pic-pca')
   */
  pcaHeader?: string;

  /**
   * Header name for outgoing PCA (default: 'x-pic-pca')
   */
  outgoingPcaHeader?: string;

  /**
   * If true, make PCA optional (request proceeds without authority context)
   */
  optional?: boolean;

  /**
   * Custom error handler for Trust Plane errors
   */
  onError?: (
    error: Error,
    req: Request,
    res: Response,
    next: NextFunction
  ) => void;
}

/**
 * Create PIC middleware for Express
 *
 * This middleware:
 * 1. Extracts PCA from request header
 * 2. Builds PoC for this hop
 * 3. Gets successor PCA from Trust Plane
 * 4. Attaches authority info to `req.pic`
 * 5. Rejects if monotonicity violated
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { picMiddleware, generateKeyPair } from '@provenance/sdk';
 *
 * const app = express();
 *
 * // Generate or load key pair
 * const keyPair = await generateKeyPair('my-service-key');
 *
 * // Register with Trust Plane
 * const client = new TrustPlaneClient('http://localhost:8080');
 * await client.registerExecutorKey(keyPair.kid, keyPair.publicKey);
 *
 * // Apply middleware
 * app.use(picMiddleware({
 *   trustPlaneUrl: 'http://localhost:8080',
 *   keyPair,
 *   serviceName: 'my-service',
 *   extractOps: (req) => {
 *     // Map request to operations
 *     const action = req.method === 'GET' ? 'read' : 'write';
 *     return [`${action}:${req.path.slice(1).replace(/\//g, ':')}`];
 *   },
 * }));
 *
 * // Access authority context in handlers
 * app.get('/claims/:id', (req, res) => {
 *   console.log(`Request from: ${req.pic?.p_0}`);
 *   console.log(`Operations: ${req.pic?.ops}`);
 *   console.log(`Hop: ${req.pic?.hop}`);
 *   // ... handle request
 * });
 * ```
 */
export function picMiddleware(options: PicMiddlewareOptions) {
  const {
    trustPlaneUrl,
    keyPair,
    extractOps,
    buildExecutor,
    serviceName = 'unknown-service',
    pcaHeader = 'x-pic-pca',
    outgoingPcaHeader = 'x-pic-pca',
    optional = false,
    onError,
  } = options;

  const client = new TrustPlaneClient(trustPlaneUrl);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get incoming PCA from header
      const pcaHeaderValue = req.headers[pcaHeader.toLowerCase()] as
        | string
        | undefined;

      if (!pcaHeaderValue) {
        if (optional) {
          // No PCA, but that's okay - proceed without authority context
          return next();
        }
        return res.status(401).json({
          error: 'Missing PCA',
          code: 'MISSING_PCA',
          message: `Request must include ${pcaHeader} header`,
        });
      }

      // Determine ops for this hop
      const ops = extractOps?.(req) ?? ['*'];

      // Build executor binding
      const executor: ExecutorBinding = buildExecutor?.(req) ?? {
        service: serviceName,
        method: req.method,
        path: req.path,
      };

      // Build PoC
      const poc = new PocBuilder(pcaHeaderValue)
        .withOps(ops)
        .withExecutor(executor)
        .build();

      // Sign PoC
      const signedPoc = await new PocBuilder(pcaHeaderValue)
        .withOps(ops)
        .withExecutor(executor)
        .sign(keyPair);

      // Process PoC to get successor PCA
      let response: ProcessPocResponse;
      try {
        response = await client.processPoc(signedPoc);
      } catch (error) {
        if (error instanceof TrustPlaneApiError) {
          if (error.code === 'MONOTONICITY_VIOLATION') {
            return res.status(403).json({
              error: 'Authority denied',
              code: error.code,
              message: error.message,
              details: error.details,
            });
          }
          if (error.code === 'UNKNOWN_EXECUTOR') {
            return res.status(401).json({
              error: 'Executor not registered',
              code: error.code,
              message: 'This service is not registered with the Trust Plane',
            });
          }
          if (error.code === 'PCA_EXPIRED') {
            return res.status(401).json({
              error: 'Authority expired',
              code: error.code,
              message: 'The predecessor PCA has expired',
            });
          }
        }
        throw error;
      }

      // Attach PIC context to request
      req.pic = {
        pca: response.pca,
        p_0: response.p_0,
        ops: response.ops,
        hop: response.hop,
      };

      // Set outgoing PCA header for downstream services
      res.setHeader(outgoingPcaHeader, response.pca);

      next();
    } catch (error) {
      if (onError) {
        return onError(error as Error, req, res, next);
      }

      console.error('[PIC Middleware] Error:', error);
      return res.status(500).json({
        error: 'Trust Plane error',
        code: 'INTERNAL_ERROR',
        message: 'Failed to process authority chain',
      });
    }
  };
}

/**
 * Middleware to require specific operations
 *
 * Use this after picMiddleware to enforce that the request has
 * specific operations in its authority chain.
 *
 * @example
 * ```typescript
 * app.get('/claims/:id',
 *   picMiddleware({ ... }),
 *   requireOps(['read:claims:*']),
 *   (req, res) => { ... }
 * );
 * ```
 */
export function requireOps(requiredOps: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.pic) {
      res.status(401).json({
        error: 'No authority context',
        code: 'MISSING_PIC_CONTEXT',
        message: 'Request does not have PIC authority context',
      });
      return;
    }

    // Check if all required ops are covered by current ops
    for (const required of requiredOps) {
      const covered = req.pic.ops.some((op) => operationCovers(op, required));
      if (!covered) {
        res.status(403).json({
          error: 'Insufficient authority',
          code: 'INSUFFICIENT_OPS',
          message: `Missing required operation: ${required}`,
          current_ops: req.pic.ops,
          required_ops: requiredOps,
        });
        return;
      }
    }

    next();
  };
}

/**
 * Check if an operation pattern covers a specific operation
 *
 * Supports wildcards:
 * - '*' matches everything
 * - 'read:*' matches 'read:anything'
 * - 'read:claims:*' matches 'read:claims:alice/123'
 */
function operationCovers(pattern: string, operation: string): boolean {
  if (pattern === '*') {
    return true;
  }

  if (pattern === operation) {
    return true;
  }

  // Handle wildcard patterns
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // Remove '*', keep ':'
    return operation.startsWith(prefix);
  }

  return false;
}

/**
 * Helper to extract PCA header value for forwarding to downstream services
 */
export function getPcaForForwarding(req: Request): string | undefined {
  return req.pic?.pca;
}

/**
 * Create headers object for forwarding PCA to downstream service
 *
 * @example
 * ```typescript
 * // Forward request to downstream service with PCA
 * const response = await fetch('http://downstream/api', {
 *   headers: {
 *     ...forwardPcaHeaders(req),
 *     'Content-Type': 'application/json',
 *   },
 *   body: JSON.stringify(data),
 * });
 * ```
 */
export function forwardPcaHeaders(
  req: Request,
  headerName = 'x-pic-pca'
): Record<string, string> {
  const pca = req.pic?.pca;
  if (!pca) {
    return {};
  }
  return { [headerName]: pca };
}

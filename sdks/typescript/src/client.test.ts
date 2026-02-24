import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TrustPlaneClient, TrustPlaneApiError } from './client.js';

/**
 * Create a mock fetch function that returns predetermined responses
 */
function mockFetch(
  status: number,
  body: unknown,
  options?: { ok?: boolean }
): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    ok: options?.ok ?? (status >= 200 && status < 300),
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(body),
  } as Response);
}

describe('TrustPlaneClient', () => {
  describe('constructor', () => {
    it('accepts a string URL', () => {
      const client = new TrustPlaneClient('http://localhost:8080');
      expect(client).toBeInstanceOf(TrustPlaneClient);
    });

    it('accepts options object', () => {
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        timeout: 5000,
        headers: { 'X-Custom': 'value' },
      });
      expect(client).toBeInstanceOf(TrustPlaneClient);
    });

    it('strips trailing slash from baseUrl', async () => {
      const fetchMock = mockFetch(200, { status: 'ok', cat_kid: 'test' });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080/',
        fetch: fetchMock,
      });

      await client.getReadyInfo();
      expect(fetchMock).toHaveBeenCalledWith(
        'http://localhost:8080/ready',
        expect.any(Object)
      );
    });
  });

  describe('issuePca', () => {
    it('posts to /v1/pca/issue', async () => {
      const responseBody = {
        pca: 'base64-pca-data',
        hop: 0,
        p_0: 'oidc:alice',
        ops: ['read:*'],
      };
      const fetchMock = mockFetch(200, responseBody);
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      const result = await client.issuePca({
        credential: 'mock:alice',
        credential_type: 'mock',
        ops: ['read:*'],
      });

      expect(result).toEqual(responseBody);
      expect(fetchMock).toHaveBeenCalledWith(
        'http://localhost:8080/v1/pca/issue',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
    });

    it('throws TrustPlaneApiError on failure', async () => {
      const fetchMock = mockFetch(
        403,
        { code: 'FORBIDDEN', message: 'No operations allowed' },
        { ok: false }
      );
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      await expect(
        client.issuePca({
          credential: 'mock:alice',
          credential_type: 'mock',
          ops: ['admin:*'],
        })
      ).rejects.toThrow(TrustPlaneApiError);
    });
  });

  describe('processPoc', () => {
    it('posts base64 string directly', async () => {
      const responseBody = {
        pca: 'base64-successor-pca',
        hop: 1,
        p_0: 'oidc:alice',
        ops: ['read:claims:*'],
      };
      const fetchMock = mockFetch(200, responseBody);
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      const result = await client.processPoc('base64-poc-data');
      expect(result).toEqual(responseBody);

      const callBody = JSON.parse(
        (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][1].body
      );
      expect(callBody.poc).toBe('base64-poc-data');
    });

    it('encodes Uint8Array to base64', async () => {
      const fetchMock = mockFetch(200, { pca: 'data', hop: 1, p_0: 'a', ops: [] });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      await client.processPoc(new Uint8Array([1, 2, 3]));

      const callBody = JSON.parse(
        (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][1].body
      );
      expect(callBody.poc).toBe(Buffer.from([1, 2, 3]).toString('base64'));
    });

    it('encodes SignedPoc object', async () => {
      const fetchMock = mockFetch(200, { pca: 'data', hop: 1, p_0: 'a', ops: [] });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      await client.processPoc({ bytes: new Uint8Array([4, 5, 6]) });

      const callBody = JSON.parse(
        (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][1].body
      );
      expect(callBody.poc).toBe(Buffer.from([4, 5, 6]).toString('base64'));
    });

    it('throws on monotonicity violation', async () => {
      const fetchMock = mockFetch(
        403,
        { code: 'MONOTONICITY_VIOLATION', message: 'ops not subset' },
        { ok: false }
      );
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      try {
        await client.processPoc('poc-data');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TrustPlaneApiError);
        expect((error as TrustPlaneApiError).code).toBe('MONOTONICITY_VIOLATION');
        expect((error as TrustPlaneApiError).status).toBe(403);
      }
    });
  });

  describe('registerExecutorKey', () => {
    it('posts key registration', async () => {
      const fetchMock = mockFetch(204, undefined);
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      await client.registerExecutorKey('my-key', new Uint8Array(32));

      const callBody = JSON.parse(
        (fetchMock as ReturnType<typeof vi.fn>).mock.calls[0][1].body
      );
      expect(callBody.kid).toBe('my-key');
      expect(callBody.public_key).toBeDefined();
    });
  });

  describe('isHealthy', () => {
    it('returns true when healthy', async () => {
      const fetchMock = mockFetch(200, { status: 'ok' });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      const healthy = await client.isHealthy();
      expect(healthy).toBe(true);
    });

    it('returns false on error', async () => {
      const fetchMock = vi.fn().mockRejectedValue(new Error('Connection refused'));
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      const healthy = await client.isHealthy();
      expect(healthy).toBe(false);
    });

    it('returns false on non-ok response', async () => {
      const fetchMock = mockFetch(503, {}, { ok: false });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      const healthy = await client.isHealthy();
      expect(healthy).toBe(false);
    });
  });

  describe('error handling', () => {
    it('handles non-JSON error responses', async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: () => Promise.reject(new Error('Not JSON')),
      } as unknown as Response);

      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        fetch: fetchMock,
      });

      try {
        await client.issuePca({
          credential: 'test',
          credential_type: 'mock',
          ops: ['read:*'],
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(TrustPlaneApiError);
        expect((error as TrustPlaneApiError).code).toBe('UNKNOWN_ERROR');
        expect((error as TrustPlaneApiError).status).toBe(500);
      }
    });

    it('includes custom headers in requests', async () => {
      const fetchMock = mockFetch(200, { status: 'ok', cat_kid: 'test' });
      const client = new TrustPlaneClient({
        baseUrl: 'http://localhost:8080',
        headers: { Authorization: 'Bearer token123' },
        fetch: fetchMock,
      });

      await client.getReadyInfo();

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer token123',
          }),
        })
      );
    });
  });
});

describe('TrustPlaneApiError', () => {
  it('preserves status, code, and message', () => {
    const error = new TrustPlaneApiError(403, {
      code: 'MONOTONICITY_VIOLATION',
      message: 'ops not subset of predecessor',
    });

    expect(error.status).toBe(403);
    expect(error.code).toBe('MONOTONICITY_VIOLATION');
    expect(error.message).toBe('ops not subset of predecessor');
    expect(error.name).toBe('TrustPlaneApiError');
    expect(error).toBeInstanceOf(Error);
  });

  it('preserves details', () => {
    const error = new TrustPlaneApiError(400, {
      code: 'INVALID_FORMAT',
      message: 'Bad request',
      details: { field: 'ops', reason: 'empty' },
    });

    expect(error.details).toEqual({ field: 'ops', reason: 'empty' });
  });
});

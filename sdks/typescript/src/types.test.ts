import { describe, it, expect } from 'vitest';
import { isTrustPlaneError, isPca0 } from './types.js';
import type { Pca, TrustPlaneError } from './types.js';

describe('isTrustPlaneError', () => {
  it('returns true for valid TrustPlaneError', () => {
    const error: TrustPlaneError = {
      code: 'MONOTONICITY_VIOLATION',
      message: 'ops not subset',
    };
    expect(isTrustPlaneError(error)).toBe(true);
  });

  it('returns true with details', () => {
    expect(
      isTrustPlaneError({
        code: 'INVALID_FORMAT',
        message: 'Bad request',
        details: { field: 'ops' },
      })
    ).toBe(true);
  });

  it('returns false for null', () => {
    expect(isTrustPlaneError(null)).toBe(false);
  });

  it('returns false for undefined', () => {
    expect(isTrustPlaneError(undefined)).toBe(false);
  });

  it('returns false for string', () => {
    expect(isTrustPlaneError('error')).toBe(false);
  });

  it('returns false for object missing code', () => {
    expect(isTrustPlaneError({ message: 'error' })).toBe(false);
  });

  it('returns false for object missing message', () => {
    expect(isTrustPlaneError({ code: 'ERROR' })).toBe(false);
  });

  it('returns false for non-string code', () => {
    expect(isTrustPlaneError({ code: 123, message: 'error' })).toBe(false);
  });
});

describe('isPca0', () => {
  it('returns true for PCA_0', () => {
    const pca: Pca = {
      hop: 0,
      p_0: { type: 'oidc', value: 'alice' },
      ops: ['read:*'],
      executor: { service: 'gateway' },
    };
    expect(isPca0(pca)).toBe(true);
  });

  it('returns false for successor PCA (hop > 0)', () => {
    const pca: Pca = {
      hop: 1,
      p_0: { type: 'oidc', value: 'alice' },
      ops: ['read:claims:*'],
      executor: { service: 'agent' },
      provenance: {
        cat_kid: 'trust-plane-1',
        cat_sig: 'sig-data',
        executor_kid: 'executor-1',
        executor_sig: 'sig-data',
      },
    };
    expect(isPca0(pca)).toBe(false);
  });

  it('returns false for hop 0 with provenance', () => {
    const pca: Pca = {
      hop: 0,
      p_0: { type: 'oidc', value: 'alice' },
      ops: ['read:*'],
      executor: { service: 'gateway' },
      provenance: {
        cat_kid: 'trust-plane-1',
        cat_sig: 'sig-data',
        executor_kid: 'executor-1',
        executor_sig: 'sig-data',
      },
    };
    // hop 0 but has provenance - isPca0 checks both conditions
    expect(isPca0(pca)).toBe(false);
  });
});

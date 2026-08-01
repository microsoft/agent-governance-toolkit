// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 action digests.
 *
 * ADR-0030 binds every approval to the exact action under review by hashing a
 * canonical serialization of the request. The same digest must be reproducible
 * at the execution boundary, so the serialization must be deterministic.
 *
 * Parity with agent-governance-python
 * agent-mesh/src/agentmesh/governance/approval_protocol/digest.py.
 * Refs #3083.
 */

import { createHash } from 'crypto';
import canonicalizeRfc8785 from 'canonicalize';

export const DIGEST_PREFIX = 'sha256:';

/** Return the RFC 8785 canonical UTF-8 encoding of value. */
export function canonicalize(value: unknown): Buffer {
  // canonicalize() returns undefined for non-serializable values (NaN, Infinity, etc.)
  const json = canonicalizeRfc8785(value as Parameters<typeof canonicalizeRfc8785>[0]);
  if (json === undefined) {
    throw new TypeError('JCS cannot serialize value (NaN, Infinity, or non-serializable type)');
  }
  return Buffer.from(json, 'utf8');
}

/** Return "sha256:<lowercase-hex>" over the JCS encoding of value. */
export function sha256Jcs(value: unknown): string {
  return DIGEST_PREFIX + createHash('sha256').update(canonicalize(value)).digest('hex');
}

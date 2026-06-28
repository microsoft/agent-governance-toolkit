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

export const DIGEST_PREFIX = 'sha256:';

function utf16Units(key: string): Buffer {
  return Buffer.from(key, 'utf16le');
}

function formatNumber(value: number): string {
  if (!isFinite(value) || isNaN(value)) {
    throw new TypeError('JCS cannot serialize NaN or Infinity');
  }
  if (Number.isInteger(value)) return String(value);
  return String(value);
}

function emit(value: unknown, out: string[]): void {
  if (value === null || value === undefined) {
    out.push('null');
    return;
  }
  if (typeof value === 'boolean') {
    out.push(value ? 'true' : 'false');
    return;
  }
  if (typeof value === 'number') {
    out.push(formatNumber(value));
    return;
  }
  if (typeof value === 'string') {
    out.push(JSON.stringify(value));
    return;
  }
  if (Array.isArray(value)) {
    out.push('[');
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out.push(',');
      emit(value[i], out);
    }
    out.push(']');
    return;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => {
      const ba = utf16Units(a);
      const bb = utf16Units(b);
      return ba.compare(bb);
    });
    out.push('{');
    for (let i = 0; i < keys.length; i++) {
      if (i > 0) out.push(',');
      out.push(JSON.stringify(keys[i]));
      out.push(':');
      emit(obj[keys[i]], out);
    }
    out.push('}');
    return;
  }
  throw new TypeError(`value of type ${typeof value} is not JCS-serializable`);
}

/** Return the RFC 8785 canonical UTF-8 encoding of value. */
export function canonicalize(value: unknown): Buffer {
  const parts: string[] = [];
  emit(value, parts);
  return Buffer.from(parts.join(''), 'utf8');
}

/** Return "sha256:<lowercase-hex>" over the JCS encoding of value. */
export function sha256Jcs(value: unknown): string {
  return DIGEST_PREFIX + createHash('sha256').update(canonicalize(value)).digest('hex');
}

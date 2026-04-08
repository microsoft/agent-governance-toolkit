// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'crypto';
import { performance } from 'perf_hooks';
import { MCPClock, MCPDebugLogger } from './types';

const DEFAULT_REGEX_SCAN_TIMEOUT_MS = 100;

export const DEFAULT_MCP_CLOCK: MCPClock = {
  now: () => Date.now(),
  monotonic: () => performance.now(),
};

export function toTimestamp(value: number | Date): number {
  return value instanceof Date ? value.getTime() : value;
}

export function normalizeSecret(secret: string | Uint8Array): Buffer {
  return typeof secret === 'string'
    ? Buffer.from(secret, 'utf-8')
    : Buffer.from(secret);
}

export class RegexScanBudget {
  private readonly startedAt: number;

  constructor(
    private readonly clock: MCPClock = DEFAULT_MCP_CLOCK,
    private readonly timeoutMs: number = DEFAULT_REGEX_SCAN_TIMEOUT_MS,
  ) {
    this.startedAt = this.monotonicNow();
  }

  checkpoint(
    publicMessage: string = 'Regex scan exceeded time budget - access denied',
  ): void {
    if (this.monotonicNow() - this.startedAt >= this.timeoutMs) {
      throw new Error(publicMessage);
    }
  }

  private monotonicNow(): number {
    return this.clock.monotonic?.() ?? performance.now();
  }
}

export function createRegexScanBudget(
  clock?: MCPClock,
  timeoutMs?: number,
): RegexScanBudget {
  return new RegexScanBudget(clock ?? DEFAULT_MCP_CLOCK, timeoutMs ?? DEFAULT_REGEX_SCAN_TIMEOUT_MS);
}

export function validateRegex(
  pattern: RegExp,
  testInput: string = `${'a'.repeat(24)}!`,
  budgetMs: number = 50,
): void {
  void testInput;
  if (hasNestedQuantifier(pattern.source)) {
    throw new Error(`Regex exceeded ${budgetMs}ms budget - possible ReDoS`);
  }
  if (hasBackreference(pattern.source) || hasRepeatedWildcard(pattern.source)) {
    throw new Error(`Regex exceeded ${budgetMs}ms budget - possible ReDoS`);
  }
}

export function debugSecurityFailure(
  logger: MCPDebugLogger | undefined,
  gate: string,
  error: unknown,
): void {
  logger?.debug?.('Security gate failed closed', {
    gate,
    error: error instanceof Error ? error.message : String(error),
  });
}

export function randomNonce(size: number = 18): string {
  return randomBytes(size).toString('base64url');
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function createHmacHex(
  secret: string | Uint8Array,
  ...parts: Array<string | number>
): string {
  const hmac = createHmac('sha256', normalizeSecret(secret));
  for (const part of parts) {
    hmac.update(String(part));
    hmac.update('\n');
  }
  return hmac.digest('hex');
}

export function timingSafeEqualHex(
  left: string,
  right: string,
): boolean {
  if (left.length !== right.length) {
    return false;
  }

  try {
    return timingSafeEqual(
      Buffer.from(left, 'hex'),
      Buffer.from(right, 'hex'),
    );
  } catch {
    return false;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function truncatePreview(value: string, max: number = 120): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
}

function canonicalize(
  value: unknown,
  seen: WeakSet<object> = new WeakSet(),
): unknown {
  if (
    value === null
    || typeof value === 'string'
    || typeof value === 'number'
    || typeof value === 'boolean'
  ) {
    return value;
  }

  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString('base64');
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item, seen));
  }

  if (typeof value === 'object' && value !== null) {
    if (seen.has(value)) {
      throw new Error('Cannot canonicalize circular structures');
    }
    seen.add(value);

    const record = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      result[key] = canonicalize(record[key], seen);
    }
    return result;
  }

  return String(value);
}

function hasNestedQuantifier(source: string): boolean {
  const groupStack: boolean[] = [];
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '(') {
      groupStack.push(false);
      continue;
    }
    if (char === ')') {
      const groupHasInnerQuantifier = groupStack.pop();
      if (!groupHasInnerQuantifier) {
        continue;
      }

      if (startsQuantifier(source, index + 1)) {
        return true;
      }
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1] = true;
      }
      continue;
    }
    if (groupStack.length > 0 && startsQuantifier(source, index)) {
      groupStack[groupStack.length - 1] = true;
    }
  }

  return false;
}

function startsQuantifier(source: string, index: number): boolean {
  const char = source[index];
  return char === '*' || char === '+' || char === '?' || char === '{';
}

function hasBackreference(source: string): boolean {
  for (let index = 0; index < source.length - 1; index += 1) {
    if (source[index] !== '\\') {
      continue;
    }
    const next = source[index + 1];
    if (next && next >= '1' && next <= '9') {
      return true;
    }
    index += 1;
  }
  return false;
}

function hasRepeatedWildcard(source: string): boolean {
  let escaped = false;
  let inCharacterClass = false;

  for (let index = 0; index < source.length - 1; index += 1) {
    const char = source[index];

    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '[') {
      inCharacterClass = true;
      continue;
    }
    if (char === ']' && inCharacterClass) {
      inCharacterClass = false;
      continue;
    }
    if (inCharacterClass || char !== '.') {
      continue;
    }

    const next = source[index + 1];
    if (next === '*' || next === '+') {
      return true;
    }
  }

  return false;
}

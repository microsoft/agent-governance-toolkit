// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'crypto';
import { performance } from 'perf_hooks';
import { Clock, McpDebugLogger, NonceGenerator } from './types';

const DEFAULT_REGEX_SCAN_TIMEOUT_MS = 100;

/**
 * Provides wall-clock and monotonic timestamps for security decisions.
 */
export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }

  monotonic(): number {
    return performance.now();
  }
}

/**
 * Generates unpredictable nonce values for replay protection.
 */
export class DefaultNonceGenerator implements NonceGenerator {
  generate(): string {
    try {
      return randomUUID();
    } catch {
      return randomBytes(16).toString('hex');
    }
  }
}

/**
 * Represents a sanitized error that is safe to surface across a security boundary.
 */
export class McpSecurityError extends Error {
  constructor(public readonly publicMessage: string) {
    super(publicMessage);
    this.name = 'McpSecurityError';
    this.stack = undefined;
  }
}

/**
 * Serializes asynchronous work for a key so concurrent calls cannot race shared state.
 */
export class AsyncKeyLock {
  private readonly tails = new Map<string, Promise<void>>();

  async run<T>(
    key: string,
    task: () => Promise<T> | T,
  ): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const next = previous.catch(() => undefined).then(() => current);
    this.tails.set(key, next);
    await previous.catch(() => undefined);

    try {
      return await task();
    } finally {
      release();
      if (this.tails.get(key) === next) {
        this.tails.delete(key);
      }
    }
  }
}

/**
 * Enforces a bounded time budget around repeated regex scans.
 */
export class RegexScanBudget {
  private readonly startedAt: number;

  constructor(
    private readonly clock: Clock = new SystemClock(),
    private readonly timeoutMs: number = DEFAULT_REGEX_SCAN_TIMEOUT_MS,
  ) {
    this.startedAt = this.clock.monotonic();
  }

  checkpoint(
    publicMessage: string = 'Regex scan exceeded time budget - access denied',
  ): void {
    if (this.clock.monotonic() - this.startedAt >= this.timeoutMs) {
      throw new McpSecurityError(publicMessage);
    }
  }
}

/**
 * Creates a reusable regex scan budget with repo-default timeout behavior.
 */
export function createRegexScanBudget(
  clock?: Clock,
  timeoutMs?: number,
): RegexScanBudget {
  return new RegexScanBudget(clock ?? new SystemClock(), timeoutMs ?? DEFAULT_REGEX_SCAN_TIMEOUT_MS);
}

/**
 * Validates a caller-supplied regex against a quick safety heuristic and time budget.
 */
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

/**
 * Emits non-sensitive debug logging for fail-closed security gates.
 */
export function debugSecurityFailure(
  logger: McpDebugLogger | undefined,
  gate: string,
  error: unknown,
): void {
  logger?.debug?.('Security gate failed closed', {
    gate,
    error: error instanceof Error ? error.message : String(error),
  });
}

/**
 * Converts an internal error into a caller-safe reason string.
 */
export function getSafeErrorMessage(
  error: unknown,
  fallback: string,
): string {
  if (error instanceof McpSecurityError) {
    return error.publicMessage;
  }
  return fallback;
}

/**
 * Normalizes HMAC secrets into byte buffers.
 */
export function normalizeSecret(secret: string | Uint8Array): Buffer {
  return typeof secret === 'string'
    ? Buffer.from(secret, 'utf-8')
    : Buffer.from(secret);
}

/**
 * Produces a stable JSON representation suitable for signing and policy checks.
 */
export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

/**
 * Computes an HMAC-SHA256 digest for the provided parts.
 */
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

/**
 * Compares hexadecimal digests without leaking timing differences.
 */
export function safeEqualHex(left: string, right: string): boolean {
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

/**
 * Truncates potentially sensitive previews before audit storage.
 */
export function truncatePreview(value: string, max: number = 80): string {
  return value.length <= max ? value : `${value.slice(0, max)}...`;
}

/**
 * Narrows unknown values to plain object records.
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Tests a regular expression from the start of its stateful cursor.
 */
export function hasMatch(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(value);
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

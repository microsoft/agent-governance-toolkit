// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  MCPMessageEnvelope,
  MCPMessageSignerConfig,
  MCPMessageVerificationResult,
  MCPNonceStore,
} from './types';
import {
  DEFAULT_MCP_CLOCK,
  debugSecurityFailure,
  createHmacHex,
  normalizeSecret,
  randomNonce,
  stableStringify,
  toTimestamp,
  timingSafeEqualHex,
} from './mcp-utils';

const DEFAULT_MAX_CLOCK_SKEW_MS = 30_000;
const DEFAULT_NONCE_TTL_MS = 5 * 60_000;

export class InMemoryMCPNonceStore implements MCPNonceStore {
  private readonly entries = new Map<string, number>();

  consume(scope: string, nonce: string, expiresAt: number): boolean {
    this.prune(scope);
    const key = `${scope}:${nonce}`;
    if (this.entries.has(key)) {
      return false;
    }
    this.entries.set(key, expiresAt);
    return true;
  }

  reset(scope?: string): void {
    if (!scope) {
      this.entries.clear();
      return;
    }

    for (const key of this.entries.keys()) {
      if (key.startsWith(`${scope}:`)) {
        this.entries.delete(key);
      }
    }
  }

  private prune(scope: string): void {
    const now = Date.now();
    for (const [key, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now || key.startsWith(`${scope}:`)) {
        if (expiresAt <= now) {
          this.entries.delete(key);
        }
      }
    }
  }
}

export class MCPMessageSigner {
  private readonly config: Required<
    Pick<MCPMessageSignerConfig, 'maxClockSkewMs' | 'nonceTtlMs'>
  > & MCPMessageSignerConfig;
  private readonly nonceStore: MCPNonceStore;

  constructor(config: MCPMessageSignerConfig) {
    const key = normalizeSecret(config.secret);
    if (key.length < 32) {
      throw new Error('HMAC secret must be at least 32 bytes');
    }
    this.config = {
      ...config,
      maxClockSkewMs: config.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS,
      nonceTtlMs: config.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS,
    };
    this.nonceStore = config.nonceStore ?? new InMemoryMCPNonceStore();
  }

  sign<T>(payload: T): MCPMessageEnvelope<T> {
    const timestamp = toTimestamp((this.config.clock ?? DEFAULT_MCP_CLOCK).now());
    const nonce = randomNonce(12);
    const signature = this.computeSignature(
      payload,
      timestamp,
      nonce,
      this.config.keyId,
    );

    return {
      payload,
      timestamp,
      nonce,
      signature,
      keyId: this.config.keyId,
    };
  }

  async verify<T>(
    envelope: MCPMessageEnvelope<T>,
  ): Promise<MCPMessageVerificationResult<T>> {
    try {
      const expectedSignature = this.computeSignature(
        envelope.payload,
        envelope.timestamp,
        envelope.nonce,
        envelope.keyId,
      );
      if (!timingSafeEqualHex(envelope.signature, expectedSignature)) {
        return { valid: false, reason: 'Signature mismatch' };
      }

      const now = toTimestamp((this.config.clock ?? DEFAULT_MCP_CLOCK).now());
      if (
        Math.abs(now - envelope.timestamp)
        > this.config.maxClockSkewMs
      ) {
        return { valid: false, reason: 'Timestamp outside accepted skew window' };
      }

      const scope = envelope.keyId ?? 'default';
      const accepted = await this.nonceStore.consume(
        scope,
        envelope.nonce,
        envelope.timestamp + this.config.nonceTtlMs,
      );
      if (!accepted) {
        return { valid: false, reason: 'Replay detected' };
      }

      return {
        valid: true,
        envelope,
      };
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'messageSigner.verify', error);
      return {
        valid: false,
        reason: 'Internal error - message rejected (fail-closed)',
      };
    }
  }

  private computeSignature(
    payload: unknown,
    timestamp: number,
    nonce: string,
    keyId?: string,
  ): string {
    return createHmacHex(
      this.config.secret,
      keyId ?? 'default',
      timestamp,
      nonce,
      stableStringify(payload),
    );
  }
}

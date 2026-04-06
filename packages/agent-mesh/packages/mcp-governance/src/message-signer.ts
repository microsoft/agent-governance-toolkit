// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  McpMessageEnvelope,
  McpMessageSignerConfig,
  McpMessageVerificationResult,
} from './types';
import { InMemoryNonceStore } from './stores';
import {
  AsyncKeyLock,
  createHmacHex,
  debugSecurityFailure,
  DefaultNonceGenerator,
  getSafeErrorMessage,
  safeEqualHex,
  stableStringify,
  SystemClock,
} from './utils';

const DEFAULT_MAX_CLOCK_SKEW_MS = 30_000;
const DEFAULT_NONCE_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_NONCE_ENTRIES = 4_096;

/**
 * Signs MCP payloads and rejects replayed or stale envelopes.
 */
export class McpMessageSigner {
  private readonly config: Required<
    Pick<McpMessageSignerConfig, 'maxClockSkewMs' | 'nonceTtlMs' | 'maxNonceEntries'>
  > & McpMessageSignerConfig;
  private readonly verificationLock = new AsyncKeyLock();

  constructor(config: McpMessageSignerConfig) {
    const clock = config.clock ?? new SystemClock();
    this.config = {
      ...config,
      maxClockSkewMs: config.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS,
      nonceTtlMs: config.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS,
      maxNonceEntries: config.maxNonceEntries ?? DEFAULT_MAX_NONCE_ENTRIES,
      nonceStore: config.nonceStore ?? new InMemoryNonceStore(clock, config.maxNonceEntries ?? DEFAULT_MAX_NONCE_ENTRIES),
      clock,
      nonceGenerator: config.nonceGenerator ?? new DefaultNonceGenerator(),
    };
  }

  sign<T>(payload: T, keyId?: string): McpMessageEnvelope<T> {
    const timestamp = this.config.clock!.now().toISOString();
    const nonce = this.config.nonceGenerator!.generate();
    const signature = createHmacHex(
      this.config.secret,
      keyId ?? 'default',
      timestamp,
      nonce,
      stableStringify(payload),
    );

    return {
      payload,
      timestamp,
      nonce,
      signature,
      keyId,
    };
  }

  async verify<T>(
    envelope: McpMessageEnvelope<T>,
  ): Promise<McpMessageVerificationResult<T>> {
    try {
      const expectedSignature = createHmacHex(
        this.config.secret,
        envelope.keyId ?? 'default',
        envelope.timestamp,
        envelope.nonce,
        stableStringify(envelope.payload),
      );

      if (!safeEqualHex(envelope.signature, expectedSignature)) {
        return { valid: false, reason: 'Signature mismatch' };
      }

      await this.config.nonceStore!.cleanup();
      const now = this.config.clock!.now();
      const timestamp = new Date(envelope.timestamp);
      if (Number.isNaN(timestamp.getTime())) {
        return { valid: false, reason: 'Invalid timestamp' };
      }
      if (Math.abs(now.getTime() - timestamp.getTime()) > this.config.maxClockSkewMs) {
        return { valid: false, reason: 'Timestamp outside accepted skew window' };
      }

      const scopedNonce = `${envelope.keyId ?? 'default'}:${envelope.nonce}`;
      return await this.verificationLock.run(scopedNonce, async () => {
        await this.config.nonceStore!.cleanup();
        if (await this.config.nonceStore!.has(scopedNonce)) {
          return { valid: false, reason: 'Replay detected' };
        }

        await this.config.nonceStore!.add(
          scopedNonce,
          new Date(timestamp.getTime() + this.config.nonceTtlMs),
        );

        return {
          valid: true,
          envelope,
        };
      });
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'messageSigner.verify', error);
      return {
        valid: false,
        reason: getSafeErrorMessage(error, 'Internal error - message rejected (fail-closed)'),
      };
    }
  }
}

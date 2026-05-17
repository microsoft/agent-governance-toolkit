// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { createHash, timingSafeEqual } from 'crypto';
import { AuditConfig, AuditEntry, LegacyPolicyDecision } from './types';

type PolicyDecision = LegacyPolicyDecision;

const GENESIS_HASH = '0'.repeat(64);

/**
 * Append-only audit log with hash-chain integrity.
 * Each entry's hash covers its content plus the previous entry's hash.
 */
export class AuditLogger {
  private readonly maxEntries: number;
  private entries: AuditEntry[] = [];
  private seamHash: string | null = null;

  constructor(config?: AuditConfig) {
    this.maxEntries = config?.maxEntries ?? 10_000;
  }

  /** Append a new audit entry and return it (with computed hash fields). */
  log(
    entry: Omit<AuditEntry, 'timestamp' | 'hash' | 'previousHash'>,
  ): AuditEntry {
    const previousHash =
      this.entries.length > 0
        ? this.entries[this.entries.length - 1].hash
        : this.seamHash ?? GENESIS_HASH;

    const timestamp = new Date().toISOString();

    const payload = JSON.stringify({
      timestamp,
      agentId: entry.agentId,
      action: entry.action,
      decision: entry.decision,
      previousHash,
    });

    const hash = createHash('sha256').update(payload).digest('hex');

    const full: AuditEntry = {
      timestamp,
      agentId: entry.agentId,
      action: entry.action,
      decision: entry.decision,
      hash,
      previousHash,
    };

    this.entries.push(full);

    // Evict oldest entries if we exceed the limit, retaining the last evicted
    // entry's hash as the seam so verify() can re-anchor the surviving chain.
    if (this.entries.length > this.maxEntries) {
      const overflow = this.entries.length - this.maxEntries;
      this.seamHash = this.entries[overflow - 1].hash;
      this.entries = this.entries.slice(overflow);
    }

    return full;
  }

  /** Verify hash-chain integrity of the entire log. */
  verify(): boolean {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const expectedPrev =
        i === 0 ? this.seamHash ?? GENESIS_HASH : this.entries[i - 1].hash;

      if (entry.previousHash !== expectedPrev) return false;

      const payload = JSON.stringify({
        timestamp: entry.timestamp,
        agentId: entry.agentId,
        action: entry.action,
        decision: entry.decision,
        previousHash: entry.previousHash,
      });

      const expectedHash = createHash('sha256').update(payload).digest('hex');
      if (!timingSafeEqual(Buffer.from(entry.hash, 'utf8'), Buffer.from(expectedHash, 'utf8'))) return false;
    }
    return true;
  }

  /** Query log entries with optional filters. */
  getEntries(filter?: {
    agentId?: string;
    action?: string;
    since?: Date;
  }): AuditEntry[] {
    let result = [...this.entries];

    if (filter?.agentId) {
      result = result.filter((e) => e.agentId === filter.agentId);
    }
    if (filter?.action) {
      result = result.filter((e) => e.action === filter.action);
    }
    if (filter?.since) {
      const since = filter.since.toISOString();
      result = result.filter((e) => e.timestamp >= since);
    }

    return result;
  }

  /** Export the full log as a JSON string. */
  exportJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /** Return the number of entries currently stored. */
  get length(): number {
    return this.entries.length;
  }
}

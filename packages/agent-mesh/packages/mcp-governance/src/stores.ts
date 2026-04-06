// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  AgentBucket,
  Clock,
  McpAuditEntry,
  McpAuditSink,
  McpMetrics,
  McpNonceStore,
  McpRateLimitStore,
  McpSession,
  McpSessionStore,
} from './types';
import { SystemClock } from './utils';

const DEFAULT_MAX_NONCE_ENTRIES = 4_096;

/**
 * In-memory session store for MCP session state.
 */
export class InMemorySessionStore implements McpSessionStore {
  private readonly sessions = new Map<string, McpSession>();
  private readonly byAgent = new Map<string, Set<string>>();

  async get(id: string): Promise<McpSession | null> {
    return this.sessions.get(id) ?? null;
  }

  async set(session: McpSession): Promise<void> {
    this.sessions.set(session.id, session);
    const bucket = this.byAgent.get(session.agentId) ?? new Set<string>();
    bucket.add(session.id);
    this.byAgent.set(session.agentId, bucket);
  }

  async delete(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) {
      return;
    }
    this.sessions.delete(id);
    const bucket = this.byAgent.get(session.agentId);
    bucket?.delete(id);
    if (bucket && bucket.size === 0) {
      this.byAgent.delete(session.agentId);
    }
  }

  async listByAgent(agentId: string): Promise<McpSession[]> {
    const ids = this.byAgent.get(agentId);
    if (!ids) {
      return [];
    }
    return [...ids]
      .map((id) => this.sessions.get(id))
      .filter((value): value is McpSession => Boolean(value));
  }
}

/**
 * In-memory replay cache with bounded entry growth.
 */
export class InMemoryNonceStore implements McpNonceStore {
  private readonly entries = new Map<string, Date>();

  constructor(
    private readonly clock: Clock = new SystemClock(),
    private readonly maxEntries: number = DEFAULT_MAX_NONCE_ENTRIES,
  ) {}

  async has(nonce: string): Promise<boolean> {
    await this.cleanup();
    const expiresAt = this.entries.get(nonce);
    if (!expiresAt) {
      return false;
    }
    this.entries.delete(nonce);
    this.entries.set(nonce, expiresAt);
    return true;
  }

  async add(nonce: string, expiresAt: Date): Promise<void> {
    await this.cleanup();
    if (this.entries.has(nonce)) {
      this.entries.delete(nonce);
    }
    this.entries.set(nonce, expiresAt);
    this.evictOverflow();
  }

  async cleanup(): Promise<void> {
    const now = this.clock.now();
    for (const [nonce, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(nonce);
      }
    }
  }

  private evictOverflow(): void {
    while (this.entries.size > Math.max(this.maxEntries, 1)) {
      const oldest = this.entries.keys().next();
      if (oldest.done) {
        return;
      }
      this.entries.delete(oldest.value);
    }
  }
}

/**
 * In-memory store for per-agent sliding-window buckets.
 */
export class InMemoryRateLimitStore implements McpRateLimitStore {
  private readonly buckets = new Map<string, AgentBucket>();

  async getBucket(agentId: string): Promise<AgentBucket | null> {
    const bucket = this.buckets.get(agentId) ?? null;
    if (!bucket) {
      return null;
    }
    this.buckets.delete(agentId);
    this.buckets.set(agentId, bucket);
    return bucket;
  }

  async setBucket(agentId: string, bucket: AgentBucket): Promise<void> {
    this.buckets.delete(agentId);
    this.buckets.set(agentId, bucket);
  }

  async deleteBucket(agentId: string): Promise<void> {
    this.buckets.delete(agentId);
  }

  async cleanupInactive(inactiveBefore: Date, maxEntries: number = Number.POSITIVE_INFINITY): Promise<void> {
    for (const [agentId, bucket] of this.buckets.entries()) {
      const lastSeenAt = bucket.lastSeenAt ?? bucket.hits[bucket.hits.length - 1];
      if (!lastSeenAt || lastSeenAt < inactiveBefore) {
        this.buckets.delete(agentId);
      }
    }

    while (this.buckets.size > maxEntries) {
      const oldest = this.buckets.keys().next();
      if (oldest.done) {
        return;
      }
      this.buckets.delete(oldest.value);
    }
  }
}

/**
 * In-memory audit sink for tests and local execution.
 */
export class InMemoryAuditSink implements McpAuditSink {
  private readonly entries: McpAuditEntry[] = [];

  async record(entry: McpAuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  getEntries(): readonly McpAuditEntry[] {
    return this.entries;
  }
}

/**
 * No-op metrics implementation for environments without telemetry wiring.
 */
export class NoopMcpMetrics implements McpMetrics {
  recordDecision(): void {}
  recordThreats(): void {}
  recordRateLimitHit(): void {}
  recordScan(): void {}
}

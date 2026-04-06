// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  AgentBucket,
  McpSlidingRateLimiterConfig,
  McpSlidingRateLimitResult,
} from './types';
import { InMemoryRateLimitStore } from './stores';
import { AsyncKeyLock, debugSecurityFailure, SystemClock } from './utils';

const DEFAULT_INACTIVE_ENTRY_TTL_MS = 5 * 60_000;

/**
 * Applies per-agent sliding-window rate limits to MCP traffic.
 */
export class McpSlidingRateLimiter {
  private readonly config: Required<
    Pick<McpSlidingRateLimiterConfig, 'inactiveEntryTtlMs'>
  > & McpSlidingRateLimiterConfig;
  private readonly agentLock = new AsyncKeyLock();

  constructor(config: McpSlidingRateLimiterConfig) {
    this.config = {
      ...config,
      store: config.store ?? new InMemoryRateLimitStore(),
      clock: config.clock ?? new SystemClock(),
      inactiveEntryTtlMs: config.inactiveEntryTtlMs ?? Math.max(config.windowMs * 4, DEFAULT_INACTIVE_ENTRY_TTL_MS),
    };
  }

  async consume(agentId: string): Promise<McpSlidingRateLimitResult> {
    return this.agentLock.run(agentId, async () => {
      try {
        const now = this.config.clock!.now();
        await this.config.store!.cleanupInactive?.(
          new Date(now.getTime() - this.config.inactiveEntryTtlMs),
          this.config.maxTrackedAgents,
        );

        const existing = (await this.config.store!.getBucket(agentId)) ?? {
          agentId,
          hits: [],
          lastSeenAt: now,
        } satisfies AgentBucket;

        const nextHits = existing.hits
          .filter((hit) => now.getTime() - hit.getTime() < this.config.windowMs);
        nextHits.push(now);

        await this.config.store!.setBucket(agentId, {
          agentId,
          hits: nextHits,
          lastSeenAt: now,
        });

        const resetAt = new Date(nextHits[0].getTime() + this.config.windowMs);
        const allowed = nextHits.length <= this.config.maxRequests;

        return {
          allowed,
          count: nextHits.length,
          limit: this.config.maxRequests,
          remaining: Math.max(this.config.maxRequests - nextHits.length, 0),
          resetAt,
          retryAfterMs: allowed ? 0 : Math.max(resetAt.getTime() - now.getTime(), 0),
        };
      } catch (error) {
        debugSecurityFailure(this.config.logger, 'slidingRateLimiter.consume', error);
        return {
          allowed: false,
          count: 0,
          limit: this.config.maxRequests,
          remaining: 0,
          resetAt: this.config.clock!.now(),
          retryAfterMs: this.config.windowMs,
        };
      }
    });
  }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpSlidingRateLimiter } from '../src/sliding-rate-limiter';
import { InMemoryRateLimitStore } from '../src/stores';

class FakeClock {
  constructor(private current: Date) {}
  now(): Date { return this.current; }
  monotonic(): number { return this.current.getTime(); }
  advance(ms: number): void { this.current = new Date(this.current.getTime() + ms); }
}

describe('McpSlidingRateLimiter', () => {
  it('uses store-backed sliding windows', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const limiter = new McpSlidingRateLimiter({
      maxRequests: 1,
      windowMs: 1_000,
      clock,
    });

    expect((await limiter.consume('agent-1')).allowed).toBe(true);
    expect((await limiter.consume('agent-1')).allowed).toBe(false);
    clock.advance(2_000);
    expect((await limiter.consume('agent-1')).allowed).toBe(true);
  });

  it('serializes concurrent updates for the same agent', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const limiter = new McpSlidingRateLimiter({
      maxRequests: 1,
      windowMs: 1_000,
      clock,
    });

    const results = await Promise.all([
      limiter.consume('agent-1'),
      limiter.consume('agent-1'),
    ]);

    expect(results.filter((result) => result.allowed)).toHaveLength(1);
    expect(results.filter((result) => !result.allowed)).toHaveLength(1);
  });

  it('evicts inactive client buckets', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const store = new InMemoryRateLimitStore();
    const limiter = new McpSlidingRateLimiter({
      maxRequests: 2,
      windowMs: 1_000,
      inactiveEntryTtlMs: 500,
      store,
      clock,
    });

    await limiter.consume('agent-1');
    clock.advance(1_000);
    await limiter.consume('agent-2');

    expect(await store.getBucket('agent-1')).toBeNull();
    expect(await store.getBucket('agent-2')).not.toBeNull();
  });
});

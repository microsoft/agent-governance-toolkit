// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpSessionAuthenticator } from '../src/session-auth';

class FakeClock {
  constructor(private current: Date) {}
  now(): Date { return this.current; }
  monotonic(): number { return this.current.getTime(); }
  advance(ms: number): void { this.current = new Date(this.current.getTime() + ms); }
}

class FakeNonceGenerator {
  private value = 0;
  generate(): string {
    this.value += 1;
    return `nonce-${this.value}`;
  }
}

describe('McpSessionAuthenticator', () => {
  it('issues and verifies tokens with injected seams', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const auth = new McpSessionAuthenticator({
      secret: 'super-secret',
      clock,
      nonceGenerator: new FakeNonceGenerator(),
    });

    const issued = await auth.issueToken('agent-1');
    const verification = await auth.verifyToken(issued.token, 'agent-1');

    expect(verification.valid).toBe(true);
    expect(verification.payload?.sessionId).toBe('nonce-1');
  });

  it('fails closed on expired tokens', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const auth = new McpSessionAuthenticator({
      secret: 'super-secret',
      ttlMs: 100,
      maxClockSkewMs: 0,
      clock,
      nonceGenerator: new FakeNonceGenerator(),
    });

    const issued = await auth.issueToken('agent-1');
    clock.advance(1_000);
    const verification = await auth.verifyToken(issued.token, 'agent-1');

    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('expired');
  });

  it('prevents concurrent session races for the same agent', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const auth = new McpSessionAuthenticator({
      secret: 'super-secret',
      maxConcurrentSessions: 1,
      clock,
      nonceGenerator: new FakeNonceGenerator(),
    });

    const results = await Promise.allSettled([
      auth.issueToken('agent-1'),
      auth.issueToken('agent-1'),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toBeDefined();
    if (rejected?.status === 'rejected') {
      expect(rejected.reason.message).toBe('Concurrent session limit exceeded');
      expect(rejected.reason.stack).toBeUndefined();
    }
  });
});

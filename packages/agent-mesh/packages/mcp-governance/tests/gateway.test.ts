// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpGateway } from '../src/gateway';
import { InMemoryAuditSink, NoopMcpMetrics } from '../src/stores';
import { ApprovalStatus } from '../src/types';

class IncrementingClock {
  private tick = 0;

  now(): Date {
    return new Date('2026-01-01T00:00:00Z');
  }

  monotonic(): number {
    this.tick += 5;
    return this.tick;
  }
}

describe('McpGateway', () => {
  it('fails closed and stores only redacted audit params', async () => {
    const auditSink = new InMemoryAuditSink();
    const gateway = new McpGateway({
      sensitiveTools: ['deploy'],
      auditSink,
      metrics: new NoopMcpMetrics(),
      approvalHandler: async () => ApprovalStatus.Approved,
    });

    const result = await gateway.evaluateToolCall('agent-1', 'deploy', {
      apiKey: 'sk-test1234567890123456',
    });

    expect(result.allowed).toBe(true);
    expect(auditSink.getEntries()[0].params).toEqual({
      apiKey: '[REDACTED]',
    });
  });

  it('denies dangerous parameters', async () => {
    const gateway = new McpGateway();
    const result = await gateway.evaluateToolCall('agent-1', 'search', {
      command: '$(whoami)',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('dangerous pattern');
  });

  it('denies requests when sanitization regex scanning times out', async () => {
    const gateway = new McpGateway({
      blockedPatterns: [/safe/],
      clock: new IncrementingClock(),
      scanTimeoutMs: 5,
    });

    const result = await gateway.evaluateToolCall('agent-1', 'search', {
      query: 'safe',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Regex scan exceeded time budget');
  });

  it('rejects pathological blocked regex patterns', () => {
    expect(() => new McpGateway({
      // codeql-suppress js/polynomial-redos -- Intentionally pathological regex to test validateRegex rejection
      blockedPatterns: [/(a+)+$/],
    })).toThrow('possible ReDoS');
  });

  it('logs when the security gate fails closed', async () => {
    const debug = jest.fn();
    const gateway = new McpGateway({
      logger: { debug },
      rateLimiter: {
        consume: async () => {
          throw new Error('rate limit store failed');
        },
      },
    });

    const result = await gateway.evaluateToolCall('agent-1', 'search', {});

    expect(result.allowed).toBe(false);
    expect(debug).toHaveBeenCalledWith('Security gate failed closed', {
      gate: 'gateway.evaluateToolCall',
      error: 'rate limit store failed',
    });
  });
});

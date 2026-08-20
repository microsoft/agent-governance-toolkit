// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { KillSwitch } from '../src/kill-switch';

describe('KillSwitch', () => {
  it('runs registered handlers and compensations', async () => {
    const events: string[] = [];
    const killSwitch = new KillSwitch();

    killSwitch.registerHandler('agent-1', async () => {
      events.push('handler');
    });

    killSwitch.registerCompensation('agent-1', async () => {
      events.push('compensation');
    });

    const result = await killSwitch.kill('agent-1', {
      action: 'tool.call',
      reason: 'breach detected',
    });

    expect(events).toEqual(['handler', 'compensation']);
    expect(result.callbacksExecuted).toBe(1);
    expect(result.compensationsExecuted).toBe(1);
  });

  it('records substitute handoff targets', async () => {
    const killSwitch = new KillSwitch();
    killSwitch.registerSubstitute('agent-1', 'agent-2');

    const result = await killSwitch.kill('agent-1', {
      reason: 'manual stop',
    });

    expect(result.handoffAgentId).toBe('agent-2');
    expect(killSwitch.getHistory()).toHaveLength(1);
  });

  describe('callback timeout', () => {
    it('abandons a hung handler instead of blocking the kill flow', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerHandler('agent-hung', () => new Promise<void>(() => {}));

      const result = await killSwitch.kill('agent-hung', { reason: 'rate_limit' });

      expect(result.callbacksExecuted).toBe(0);
      expect(killSwitch.getHistory()).toHaveLength(1);
    });

    it('bounds the compensation loop as well', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerCompensation('agent-hung', () => new Promise<void>(() => {}));

      const result = await killSwitch.kill('agent-hung', { reason: 'rate_limit' });

      expect(result.compensationsExecuted).toBe(0);
    });

    it('keeps running later handlers after one hangs', async () => {
      const ran: string[] = [];
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerHandler('agent-1', () => new Promise<void>(() => {}));
      killSwitch.registerHandler('agent-1', () => {
        ran.push('second');
      });

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(ran).toEqual(['second']);
      expect(result.callbacksExecuted).toBe(1);
    });

    it('records the kill when a handler throws instead of propagating', async () => {
      const killSwitch = new KillSwitch();
      killSwitch.registerHandler('agent-throws', () => {
        throw new Error('handler blew up');
      });

      const result = await killSwitch.kill('agent-throws', { reason: 'breach detected' });

      expect(result.callbacksExecuted).toBe(0);
      expect(killSwitch.getHistory()).toHaveLength(1);
    });

    it('records the kill when a handler rejects', async () => {
      const killSwitch = new KillSwitch();
      killSwitch.registerHandler('agent-rejects', async () => {
        throw new Error('async handler blew up');
      });

      const result = await killSwitch.kill('agent-rejects', { reason: 'breach detected' });

      expect(result.callbacksExecuted).toBe(0);
      expect(killSwitch.getHistory()).toHaveLength(1);
    });

    it('counts handlers that complete within the budget', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 500 });
      killSwitch.registerHandler('agent-1', async () => {
        await new Promise((resolve) => setTimeout(resolve, 1));
      });

      const result = await killSwitch.kill('agent-1', { reason: 'manual stop' });

      expect(result.callbacksExecuted).toBe(1);
    });
  });
});

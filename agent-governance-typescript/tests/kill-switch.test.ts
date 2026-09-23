// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  DEFAULT_CALLBACK_TIMEOUT_MS,
  KillSwitch,
  MAX_CALLBACK_TIMEOUT_MS,
} from '../src/kill-switch';

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
    expect(result.terminated).toBe(true);
    expect(result.callbacksExecuted).toBe(1);
    expect(result.compensationsExecuted).toBe(1);
  });

  it('reports unsuccessful termination when no handler is registered', async () => {
    const killSwitch = new KillSwitch();

    const result = await killSwitch.kill('agent-no-handlers', {
      reason: 'manual stop',
    });

    expect(result.terminated).toBe(false);
    expect(result.callbacksExecuted).toBe(0);
    expect(killSwitch.getHistory()[0]?.terminated).toBe(false);
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

  describe('callback timeout validation', () => {
    let warn: jest.SpyInstance;

    beforeEach(() => {
      warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
      warn.mockRestore();
    });

    // A degenerate budget reaches setTimeout as a ~1ms delay, which would
    // abandon every async callback after a tick and report a kill that never
    // happened. Each case must fall back to the default budget instead.
    it.each([
      ['zero', 0],
      ['negative', -1],
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
    ])('falls back to the default budget for a %s timeout', async (_label, timeout) => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: timeout });
      killSwitch.registerHandler('agent-1', async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
      });

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(result.callbacksExecuted).toBe(1);
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining(`falling back to ${DEFAULT_CALLBACK_TIMEOUT_MS}ms`),
      );
    });

    it('clamps a budget beyond the timer ceiling instead of wrapping to 1ms', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: MAX_CALLBACK_TIMEOUT_MS + 1 });
      killSwitch.registerHandler('agent-1', async () => {
        await new Promise((resolve) => setTimeout(resolve, 5));
      });

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(result.callbacksExecuted).toBe(1);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('clamping to it'));
    });

    it('accepts a valid budget without warning', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerHandler('agent-hung', () => new Promise<void>(() => {}));

      const result = await killSwitch.kill('agent-hung', { reason: 'rate_limit' });

      expect(result.callbacksExecuted).toBe(0);
      expect(warn).not.toHaveBeenCalledWith(expect.stringContaining('callbackTimeoutMs'));
    });
  });

  // `terminated` counts handlers that finished, not handlers that were
  // registered: under a bounded callback a registered handler can be abandoned,
  // and reporting containment for one would be a fail-open on the signal
  // operators check.
  describe('termination status', () => {
    it('reports unsuccessful termination when the only handler hangs', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerHandler('agent-hung', () => new Promise<void>(() => {}));

      const result = await killSwitch.kill('agent-hung', { reason: 'breach detected' });

      expect(result.terminated).toBe(false);
      expect(result.callbacksExecuted).toBe(0);
    });

    it('reports unsuccessful termination when the only handler rejects', async () => {
      const killSwitch = new KillSwitch();
      killSwitch.registerHandler('agent-rejects', async () => {
        throw new Error('async handler blew up');
      });

      const result = await killSwitch.kill('agent-rejects', { reason: 'breach detected' });

      expect(result.terminated).toBe(false);
    });

    it('reports unsuccessful termination when only one of several handlers completes', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 20 });
      killSwitch.registerHandler('agent-1', () => new Promise<void>(() => {}));
      killSwitch.registerHandler('agent-1', () => {});

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(result.terminated).toBe(false);
      expect(result.callbacksExecuted).toBe(1);
    });

    it('reports successful termination when every handler completes', async () => {
      const killSwitch = new KillSwitch({ callbackTimeoutMs: 500 });
      killSwitch.registerHandler('agent-1', () => {});
      killSwitch.registerHandler('agent-1', async () => {
        await new Promise((resolve) => setTimeout(resolve, 1));
      });

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(result.terminated).toBe(true);
      expect(result.callbacksExecuted).toBe(2);
    });

    it('does not treat a completed compensation as termination', async () => {
      const killSwitch = new KillSwitch();
      killSwitch.registerCompensation('agent-1', () => {});

      const result = await killSwitch.kill('agent-1', { reason: 'breach detected' });

      expect(result.terminated).toBe(false);
      expect(result.compensationsExecuted).toBe(1);
    });
  });
});

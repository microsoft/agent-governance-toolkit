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
});

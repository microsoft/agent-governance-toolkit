// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { ExecutionRing } from '../src/types';
import { RingBreachError, RingEnforcer } from '../src/rings';

describe('RingEnforcer', () => {
  it('allows actions within the configured execution ring', () => {
    const enforcer = new RingEnforcer({
      agentRing: ExecutionRing.Ring1,
      defaultRing: ExecutionRing.Ring3,
      actionRings: {
        'admin.*': ExecutionRing.Ring0,
        'data.*': ExecutionRing.Ring2,
      },
    });

    expect(() => enforcer.enforce('data.read')).not.toThrow();
  });

  it('denies actions that require a more privileged ring', () => {
    const enforcer = new RingEnforcer({
      agentRing: ExecutionRing.Ring2,
      actionRings: {
        'admin.*': ExecutionRing.Ring0,
      },
    });

    expect(() => enforcer.enforce('admin.rotate')).toThrow(RingBreachError);
  });

  it('supports wildcard matching', () => {
    const enforcer = new RingEnforcer({
      agentRing: ExecutionRing.Ring3,
      defaultRing: ExecutionRing.Ring3,
      actionRings: {
        '*': ExecutionRing.Ring3,
      },
    });

    expect(enforcer.getRequiredRing('anything.at.all')).toBe(ExecutionRing.Ring3);
  });
});

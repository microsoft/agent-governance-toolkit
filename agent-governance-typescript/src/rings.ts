// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { ExecutionControlConfig, ExecutionRing, RingViolation } from './types';

export class RingBreachError extends Error {
  readonly violation: RingViolation;

  constructor(violation: RingViolation) {
    super(violation.message);
    this.name = 'RingBreachError';
    this.violation = violation;
  }
}

export class RingEnforcer {
  private readonly agentRing: ExecutionRing;
  private readonly defaultRing: ExecutionRing;
  private readonly actionRings: Record<string, ExecutionRing>;

  constructor(config: ExecutionControlConfig = {}) {
    this.agentRing = config.agentRing ?? ExecutionRing.Ring3;
    this.defaultRing = config.defaultRing ?? ExecutionRing.Ring3;
    this.actionRings = config.actionRings ?? {};
  }

  getAgentRing(): ExecutionRing {
    return this.agentRing;
  }

  getRequiredRing(action: string): ExecutionRing {
    for (const [pattern, ring] of Object.entries(this.actionRings)) {
      if (this.matches(pattern, action)) {
        return ring;
      }
    }

    return this.defaultRing;
  }

  canExecute(action: string): boolean {
    return this.agentRing <= this.getRequiredRing(action);
  }

  enforce(action: string): void {
    if (this.canExecute(action)) {
      return;
    }

    throw new RingBreachError({
      action,
      agentRing: this.agentRing,
      requiredRing: this.getRequiredRing(action),
      message: `Execution ring breach for action "${action}": agent ring ${this.agentRing} exceeds required ring ${this.getRequiredRing(action)}`,
    });
  }

  private matches(pattern: string, action: string): boolean {
    if (pattern === '*') {
      return true;
    }

    if (pattern.endsWith('*')) {
      return action.startsWith(pattern.slice(0, -1));
    }

    return pattern === action;
  }
}

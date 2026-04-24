// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── Agent Lifecycle Manager ──
// State-machine that governs an agent's lifecycle from provisioning to
// decommission, enforcing valid transitions and recording an event log.

/** Valid lifecycle states for a managed agent. */
export enum LifecycleState {
  Provisioning = 'provisioning',
  Active = 'active',
  Suspended = 'suspended',
  Rotating = 'rotating',
  Degraded = 'degraded',
  Quarantined = 'quarantined',
  Decommissioning = 'decommissioning',
  Decommissioned = 'decommissioned',
}

/** A recorded lifecycle transition event. */
export interface LifecycleEvent {
  agent_id: string;
  from_state: LifecycleState;
  to_state: LifecycleState;
  reason: string;
  timestamp: string;
  initiated_by: string;
}

/** Allowed transitions keyed by current state. */
const VALID_TRANSITIONS: Record<LifecycleState, LifecycleState[]> = {
  [LifecycleState.Provisioning]: [LifecycleState.Active],
  [LifecycleState.Active]: [
    LifecycleState.Suspended,
    LifecycleState.Rotating,
    LifecycleState.Degraded,
    LifecycleState.Quarantined,
    LifecycleState.Decommissioning,
  ],
  [LifecycleState.Suspended]: [
    LifecycleState.Active,
    LifecycleState.Decommissioning,
  ],
  [LifecycleState.Rotating]: [
    LifecycleState.Active,
    LifecycleState.Degraded,
  ],
  [LifecycleState.Degraded]: [
    LifecycleState.Active,
    LifecycleState.Quarantined,
    LifecycleState.Decommissioning,
  ],
  [LifecycleState.Quarantined]: [
    LifecycleState.Active,
    LifecycleState.Decommissioning,
  ],
  [LifecycleState.Decommissioning]: [LifecycleState.Decommissioned],
  [LifecycleState.Decommissioned]: [],
};

/**
 * Manages the lifecycle of a single agent, enforcing valid state transitions
 * and maintaining an ordered event log.
 */
export class LifecycleManager {
  private _state: LifecycleState = LifecycleState.Provisioning;
  private readonly _events: LifecycleEvent[] = [];
  private readonly _agentId: string;

  constructor(agentId: string) {
    this._agentId = agentId;
  }

  /** Current lifecycle state. */
  get state(): LifecycleState {
    return this._state;
  }

  /** Ordered list of recorded lifecycle events. */
  get events(): LifecycleEvent[] {
    return [...this._events];
  }

  /**
   * Transition to `toState`. Throws if the transition is not allowed from
   * the current state.
   */
  transition(toState: LifecycleState, reason: string, initiatedBy: string): LifecycleEvent {
    if (!this.canTransition(toState)) {
      throw new Error(
        `Invalid lifecycle transition: ${this._state} → ${toState}`,
      );
    }

    const event: LifecycleEvent = {
      agent_id: this._agentId,
      from_state: this._state,
      to_state: toState,
      reason,
      timestamp: new Date().toISOString(),
      initiated_by: initiatedBy,
    };

    this._state = toState;
    this._events.push(event);
    return event;
  }

  /** Check whether a transition to `toState` is valid from the current state. */
  canTransition(toState: LifecycleState): boolean {
    return VALID_TRANSITIONS[this._state].includes(toState);
  }

  // ── Convenience methods ──

  /** Activate the agent (from provisioning, suspended, rotating, degraded, or quarantined). */
  activate(reason: string = 'Agent activated'): LifecycleEvent {
    return this.transition(LifecycleState.Active, reason, 'system');
  }

  /** Suspend the agent. */
  suspend(reason: string): LifecycleEvent {
    return this.transition(LifecycleState.Suspended, reason, 'system');
  }

  /** Quarantine the agent due to a security or trust issue. */
  quarantine(reason: string): LifecycleEvent {
    return this.transition(LifecycleState.Quarantined, reason, 'system');
  }

  /** Begin decommissioning the agent. */
  decommission(reason: string): LifecycleEvent {
    return this.transition(LifecycleState.Decommissioning, reason, 'system');
  }
}

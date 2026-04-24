// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { LifecycleManager, LifecycleState } from '../src/lifecycle';

describe('LifecycleManager', () => {
  let lm: LifecycleManager;

  beforeEach(() => {
    lm = new LifecycleManager('agent-1');
  });

  describe('initial state', () => {
    it('starts in Provisioning', () => {
      expect(lm.state).toBe(LifecycleState.Provisioning);
    });

    it('has an empty event log', () => {
      expect(lm.events).toHaveLength(0);
    });
  });

  // ── Valid transitions ──

  describe('valid transitions', () => {
    it('provisioning → active', () => {
      const event = lm.activate('Initial activation');
      expect(lm.state).toBe(LifecycleState.Active);
      expect(event.from_state).toBe(LifecycleState.Provisioning);
      expect(event.to_state).toBe(LifecycleState.Active);
      expect(event.agent_id).toBe('agent-1');
      expect(event.reason).toBe('Initial activation');
      expect(event.initiated_by).toBe('system');
      expect(event.timestamp).toBeTruthy();
    });

    it('active → suspended → active', () => {
      lm.activate();
      lm.suspend('Maintenance window');
      expect(lm.state).toBe(LifecycleState.Suspended);
      lm.activate('Maintenance complete');
      expect(lm.state).toBe(LifecycleState.Active);
    });

    it('active → quarantined', () => {
      lm.activate();
      lm.quarantine('Trust score dropped below threshold');
      expect(lm.state).toBe(LifecycleState.Quarantined);
    });

    it('active → rotating → active', () => {
      lm.activate();
      lm.transition(LifecycleState.Rotating, 'Key rotation', 'admin');
      expect(lm.state).toBe(LifecycleState.Rotating);
      lm.activate('Rotation complete');
      expect(lm.state).toBe(LifecycleState.Active);
    });

    it('active → degraded → quarantined → decommissioning → decommissioned', () => {
      lm.activate();
      lm.transition(LifecycleState.Degraded, 'Partial failure', 'monitor');
      expect(lm.state).toBe(LifecycleState.Degraded);
      lm.quarantine('Escalated to quarantine');
      expect(lm.state).toBe(LifecycleState.Quarantined);
      lm.decommission('End of life');
      expect(lm.state).toBe(LifecycleState.Decommissioning);
      lm.transition(LifecycleState.Decommissioned, 'Cleanup done', 'system');
      expect(lm.state).toBe(LifecycleState.Decommissioned);
    });

    it('suspended → decommissioning', () => {
      lm.activate();
      lm.suspend('Pause');
      lm.decommission('No longer needed');
      expect(lm.state).toBe(LifecycleState.Decommissioning);
    });

    it('rotating → degraded', () => {
      lm.activate();
      lm.transition(LifecycleState.Rotating, 'Rotation', 'admin');
      lm.transition(LifecycleState.Degraded, 'Rotation failed', 'admin');
      expect(lm.state).toBe(LifecycleState.Degraded);
    });

    it('degraded → active (recovery)', () => {
      lm.activate();
      lm.transition(LifecycleState.Degraded, 'Error', 'monitor');
      lm.activate('Recovered');
      expect(lm.state).toBe(LifecycleState.Active);
    });

    it('degraded → decommissioning', () => {
      lm.activate();
      lm.transition(LifecycleState.Degraded, 'Error', 'monitor');
      lm.decommission('Cannot recover');
      expect(lm.state).toBe(LifecycleState.Decommissioning);
    });

    it('quarantined → active (cleared)', () => {
      lm.activate();
      lm.quarantine('Suspicious');
      lm.activate('Investigation cleared');
      expect(lm.state).toBe(LifecycleState.Active);
    });
  });

  // ── Invalid transitions ──

  describe('invalid transitions', () => {
    it('throws on provisioning → suspended', () => {
      expect(() => lm.suspend('nope')).toThrow(/Invalid lifecycle transition/);
    });

    it('throws on provisioning → decommissioned', () => {
      expect(() => lm.transition(LifecycleState.Decommissioned, 'nope', 'x')).toThrow(
        /Invalid lifecycle transition/,
      );
    });

    it('throws on decommissioned → active', () => {
      lm.activate();
      lm.decommission('bye');
      lm.transition(LifecycleState.Decommissioned, 'done', 'system');
      expect(() => lm.activate('try again')).toThrow(/Invalid lifecycle transition/);
    });

    it('throws on active → provisioning (backwards)', () => {
      lm.activate();
      expect(() => lm.transition(LifecycleState.Provisioning, 'nope', 'x')).toThrow(
        /Invalid lifecycle transition/,
      );
    });

    it('throws on suspended → quarantined (not a direct path)', () => {
      lm.activate();
      lm.suspend('pause');
      expect(() => lm.quarantine('nope')).toThrow(/Invalid lifecycle transition/);
    });
  });

  // ── canTransition ──

  describe('canTransition()', () => {
    it('returns true for valid transitions', () => {
      expect(lm.canTransition(LifecycleState.Active)).toBe(true);
    });

    it('returns false for invalid transitions', () => {
      expect(lm.canTransition(LifecycleState.Decommissioned)).toBe(false);
    });
  });

  // ── Event log ──

  describe('event log', () => {
    it('records events in order', () => {
      lm.activate();
      lm.suspend('pause');
      lm.activate('resume');

      const events = lm.events;
      expect(events).toHaveLength(3);
      expect(events[0].to_state).toBe(LifecycleState.Active);
      expect(events[1].to_state).toBe(LifecycleState.Suspended);
      expect(events[2].to_state).toBe(LifecycleState.Active);
    });

    it('returns a copy (immutable)', () => {
      lm.activate();
      const events = lm.events;
      events.push({} as never);
      expect(lm.events).toHaveLength(1);
    });

    it('includes custom initiatedBy from transition()', () => {
      const event = lm.transition(LifecycleState.Active, 'boot', 'admin-user');
      expect(event.initiated_by).toBe('admin-user');
    });
  });
});

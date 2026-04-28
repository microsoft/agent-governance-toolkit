// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { CascadeContainmentManager } from '../src/cascade-containment';

describe('CascadeContainmentManager', () => {
  let manager: CascadeContainmentManager;

  beforeEach(() => {
    manager = new CascadeContainmentManager();
  });

  describe('registerAgent()', () => {
    it('registers an agent with default trust tier', () => {
      const node = manager.registerAgent('agent-a');
      expect(node.agentId).toBe('agent-a');
      expect(node.trustTier).toBe('Provisional');
      expect(node.healthStatus).toBe('healthy');
    });

    it('registers an agent with specified trust tier', () => {
      const node = manager.registerAgent('agent-a', 'Verified');
      expect(node.trustTier).toBe('Verified');
    });

    it('returns existing node on duplicate registration', () => {
      const first = manager.registerAgent('agent-a', 'Trusted');
      const second = manager.registerAgent('agent-a', 'Untrusted');
      expect(second.trustTier).toBe('Trusted');
      expect(first).toBe(second);
    });
  });

  describe('addDependency()', () => {
    it('creates a dependency link between two agents', () => {
      manager.registerAgent('a');
      manager.registerAgent('b');
      manager.addDependency('a', 'b');

      const graph = manager.getGraph();
      const nodeA = graph.find((n) => n.agentId === 'a')!;
      const nodeB = graph.find((n) => n.agentId === 'b')!;

      expect(nodeA.dependencies).toContain('b');
      expect(nodeB.dependents).toContain('a');
    });

    it('auto-registers agents if not yet registered', () => {
      manager.addDependency('x', 'y');
      expect(manager.getGraph()).toHaveLength(2);
    });

    it('does not duplicate dependencies', () => {
      manager.addDependency('a', 'b');
      manager.addDependency('a', 'b');
      const nodeA = manager.getGraph().find((n) => n.agentId === 'a')!;
      expect(nodeA.dependencies.filter((d) => d === 'b')).toHaveLength(1);
    });

    it('enforces max fanout per trust tier', () => {
      manager.registerAgent('hub', 'Untrusted');
      // Untrusted default maxFanout is 3
      manager.addDependency('hub', 'dep-1');
      manager.addDependency('hub', 'dep-2');
      manager.addDependency('hub', 'dep-3');
      expect(() => manager.addDependency('hub', 'dep-4')).toThrow(/max fanout/);
    });

    it('enforces max dependency depth per trust tier', () => {
      // Untrusted maxDependencyDepth is 2
      manager.registerAgent('a', 'Untrusted');
      manager.registerAgent('b');
      manager.registerAgent('c');
      manager.registerAgent('d');
      manager.addDependency('b', 'c');
      manager.addDependency('c', 'd');
      // a -> b (depth via b is 2+1=3 > 2)
      expect(() => manager.addDependency('a', 'b')).toThrow(/depth/);
    });
  });

  describe('canCall() / recordSuccess() / recordFailure()', () => {
    beforeEach(() => {
      manager.registerAgent('caller');
      manager.registerAgent('callee');
      manager.addDependency('caller', 'callee');
    });

    it('allows calls when circuit breaker is closed', () => {
      expect(manager.canCall('caller', 'callee')).toBe(true);
    });

    it('opens circuit breaker after threshold failures', () => {
      // Default Provisional threshold is 4
      for (let i = 0; i < 4; i++) {
        manager.recordFailure('caller', 'callee', 'timeout');
      }
      expect(manager.canCall('caller', 'callee')).toBe(false);
      expect(manager.getBreakerState('caller', 'callee')).toBe('open');
    });

    it('emits circuit_opened event when breaker trips', () => {
      for (let i = 0; i < 4; i++) {
        manager.recordFailure('caller', 'callee', 'timeout');
      }
      const events = manager.getEvents();
      expect(events.some((e) => e.action === 'circuit_opened')).toBe(true);
    });

    it('resets circuit breaker on success', () => {
      for (let i = 0; i < 3; i++) {
        manager.recordFailure('caller', 'callee');
      }
      manager.recordSuccess('caller', 'callee');
      expect(manager.getBreakerState('caller', 'callee')).toBe('closed');
    });

    it('returns true for unregistered links', () => {
      expect(manager.canCall('unknown-a', 'unknown-b')).toBe(true);
    });
  });

  describe('health propagation', () => {
    it('propagates health degradation to dependents', () => {
      // Use Trusted agents (no auto-quarantine) with low cascade threshold
      const mgr = new CascadeContainmentManager({ cascadeThreshold: 1 });
      mgr.registerAgent('a', 'Trusted');
      mgr.registerAgent('b', 'Trusted');
      mgr.registerAgent('c', 'Trusted');
      mgr.addDependency('a', 'b');
      mgr.addDependency('b', 'c');

      // Trip breaker b->c (Trusted threshold is 5)
      for (let i = 0; i < 6; i++) {
        mgr.recordFailure('b', 'c', 'fail');
      }

      // c is now 'failing' (Trusted doesn't auto-quarantine)
      expect(mgr.getGraph().find((n) => n.agentId === 'c')!.healthStatus).toBe('failing');

      // Propagate to b (which depends on c as a dependency, but c's dependent is b)
      const events = mgr.propagateHealth('c');
      expect(events.length).toBeGreaterThan(0);
      expect(events[0].action).toBe('health_propagated');
      expect(mgr.getGraph().find((n) => n.agentId === 'b')!.healthStatus).toBe('degraded');
    });

    it('does not propagate from healthy agents', () => {
      manager.registerAgent('a');
      manager.registerAgent('b');
      manager.registerAgent('c');
      manager.addDependency('a', 'b');
      manager.addDependency('b', 'c');
      const events = manager.propagateHealth('c');
      expect(events).toHaveLength(0);
    });
  });

  describe('blast radius', () => {
    it('computes zero blast radius for leaf nodes', () => {
      manager.registerAgent('leaf');
      expect(manager.computeBlastRadius('leaf')).toBe(0);
    });

    it('computes blast radius for node with dependents', () => {
      // a, b, c all depend on service-x
      manager.registerAgent('service-x');
      manager.addDependency('a', 'service-x');
      manager.addDependency('b', 'service-x');
      manager.addDependency('c', 'service-x');
      expect(manager.computeBlastRadius('service-x')).toBe(3);
    });

    it('computes transitive blast radius', () => {
      // gateway -> service -> database
      // gateway depends on service, client depends on gateway
      manager.addDependency('client', 'gateway');
      manager.addDependency('gateway', 'service');
      manager.addDependency('service', 'database');
      // database failing affects service, gateway, client
      expect(manager.computeBlastRadius('database')).toBe(3);
    });
  });

  describe('containment policies', () => {
    it('applies stricter policy for untrusted agents', () => {
      const untrustedPolicy = manager.getPolicyForTier('Untrusted');
      const verifiedPolicy = manager.getPolicyForTier('Verified');
      expect(untrustedPolicy.maxFanout).toBeLessThan(verifiedPolicy.maxFanout);
      expect(untrustedPolicy.circuitBreakerThreshold).toBeLessThan(verifiedPolicy.circuitBreakerThreshold);
      expect(untrustedPolicy.autoQuarantine).toBe(true);
    });

    it('auto-quarantines untrusted failing agent', () => {
      manager.registerAgent('bad-agent', 'Untrusted');
      manager.registerAgent('victim');
      manager.registerAgent('victim-2');
      manager.registerAgent('victim-3');
      manager.addDependency('victim', 'bad-agent');
      manager.addDependency('victim-2', 'bad-agent');
      manager.addDependency('victim-3', 'bad-agent');

      // Provisional callers have threshold 4, need 4+ failures to trip each breaker
      for (let i = 0; i < 5; i++) {
        manager.recordFailure('victim', 'bad-agent', 'error');
      }
      for (let i = 0; i < 5; i++) {
        manager.recordFailure('victim-2', 'bad-agent', 'error');
      }
      for (let i = 0; i < 5; i++) {
        manager.recordFailure('victim-3', 'bad-agent', 'error');
      }

      const events = manager.getEvents();
      expect(events.some((e) => e.action === 'agent_quarantined')).toBe(true);
    });

    it('does not auto-quarantine verified agents by default', () => {
      manager.registerAgent('trusted-svc', 'Verified');
      manager.registerAgent('caller-1');
      manager.addDependency('caller-1', 'trusted-svc');

      for (let i = 0; i < 10; i++) {
        manager.recordFailure('caller-1', 'trusted-svc', 'error');
      }

      const events = manager.getEvents();
      expect(events.some((e) => e.action === 'agent_quarantined')).toBe(false);
    });

    it('allows custom policy overrides', () => {
      const custom = new CascadeContainmentManager({
        defaultPolicy: {
          maxDependencyDepth: 2,
          maxFanout: 2,
          circuitBreakerThreshold: 2,
          circuitBreakerResetMs: 1000,
          autoQuarantine: true,
          autoRollback: true,
        },
      });
      const policy = custom.getPolicyForTier('Verified');
      expect(policy.maxFanout).toBe(20); // Tier defaults override
    });
  });

  describe('analyze()', () => {
    it('returns correct analysis for healthy graph', () => {
      manager.registerAgent('a');
      manager.registerAgent('b');
      manager.addDependency('a', 'b');

      const analysis = manager.analyze();
      expect(analysis.totalAgents).toBe(2);
      expect(analysis.healthyAgents).toBe(2);
      expect(analysis.cascadeRisk).toBe('low');
    });

    it('returns correct analysis for degraded graph', () => {
      manager.registerAgent('a');
      manager.registerAgent('b');
      manager.addDependency('a', 'b');

      // Trip breaker to degrade
      for (let i = 0; i < 5; i++) {
        manager.recordFailure('a', 'b', 'fail');
      }

      const analysis = manager.analyze();
      expect(analysis.openCircuitBreakers).toBeGreaterThan(0);
      expect(analysis.cascadeRisk).not.toBe('low');
    });

    it('includes blast radius map', () => {
      manager.addDependency('a', 'b');
      manager.addDependency('c', 'b');

      const analysis = manager.analyze();
      expect(analysis.blastRadiusMap['b']).toBe(2);
    });

    it('returns empty analysis for empty graph', () => {
      const analysis = manager.analyze();
      expect(analysis.totalAgents).toBe(0);
      expect(analysis.cascadeRisk).toBe('low');
    });
  });

  describe('resetAgent()', () => {
    it('resets a failing agent to healthy', () => {
      manager.registerAgent('svc', 'Untrusted');
      manager.addDependency('caller', 'svc');
      for (let i = 0; i < 10; i++) {
        manager.recordFailure('caller', 'svc');
      }

      manager.resetAgent('svc');
      const node = manager.getGraph().find((n) => n.agentId === 'svc')!;
      expect(node.healthStatus).toBe('healthy');
    });
  });
});

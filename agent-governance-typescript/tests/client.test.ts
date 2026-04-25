// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentMeshClient } from '../src/client';
import { ExecutionRing } from '../src/types';

describe('AgentMeshClient', () => {
  let client: AgentMeshClient;

  beforeEach(() => {
    client = AgentMeshClient.create('test-agent', {
      capabilities: ['read', 'write'],
      policyRules: [
        { action: 'data.read', effect: 'allow' },
        { action: 'data.write', effect: 'allow', conditions: { role: 'admin' } },
        { action: 'data.delete', effect: 'deny' },
      ],
    });
  });

  describe('create()', () => {
    it('creates a client with a valid identity', () => {
      expect(client.identity.did).toMatch(/^did:agentmesh:test-agent:/);
    });

    it('exposes trust, policy, and audit subsystems', () => {
      expect(client.trust).toBeDefined();
      expect(client.policy).toBeDefined();
      expect(client.audit).toBeDefined();
      expect(client.lifecycle).toBeDefined();
    });
  });

  describe('executeWithGovernance()', () => {
    it('allows permitted actions', async () => {
      const result = await client.executeWithGovernance('data.read');
      expect(result.decision).toBe('allow');
      expect(result.trustScore).toBeDefined();
      expect(result.auditEntry).toBeDefined();
      expect(result.executionTime).toBeGreaterThanOrEqual(0);
    });

    it('denies forbidden actions', async () => {
      const result = await client.executeWithGovernance('data.delete');
      expect(result.decision).toBe('deny');
    });

    it('evaluates conditions', async () => {
      const allowed = await client.executeWithGovernance('data.write', { role: 'admin' });
      expect(allowed.decision).toBe('allow');

      const denied = await client.executeWithGovernance('data.write', { role: 'user' });
      expect(denied.decision).toBe('deny');
    });

    it('creates an audit entry for each action', async () => {
      await client.executeWithGovernance('data.read');
      await client.executeWithGovernance('data.delete');

      const entries = client.audit.getEntries();
      expect(entries).toHaveLength(2);
      expect(client.audit.verify()).toBe(true);
    });

    it('updates trust score after actions', async () => {
      const before = client.trust.getTrustScore(client.identity.did);

      await client.executeWithGovernance('data.read'); // allow ΓåÆ success
      const afterSuccess = client.trust.getTrustScore(client.identity.did);
      expect(afterSuccess.overall).toBeGreaterThanOrEqual(before.overall);

      await client.executeWithGovernance('data.delete'); // deny ΓåÆ failure
      const afterFailure = client.trust.getTrustScore(client.identity.did);
      expect(afterFailure.overall).toBeLessThan(afterSuccess.overall);
    });

    it('returns execution time', async () => {
      const result = await client.executeWithGovernance('data.read');
      expect(typeof result.executionTime).toBe('number');
    });

    it('activates lifecycle on first governance execution', async () => {
      expect(client.lifecycle.state).toBe('provisioning');
      await client.executeWithGovernance('data.read');
      expect(client.lifecycle.state).toBe('active');
    });

    it('quarantines and denies on ring breaches', async () => {
      const ringScopedClient = AgentMeshClient.create('ring-agent', {
        policyRules: [{ action: '*', effect: 'allow' }],
        execution: {
          agentRing: ExecutionRing.Ring2,
          actionRings: {
            'admin.*': ExecutionRing.Ring0,
          },
        },
      });

      const result = await ringScopedClient.executeWithGovernance('admin.shutdown');
      expect(result.decision).toBe('deny');
      expect(result.ringViolation).toBeDefined();
      expect(result.lifecycleState).toBe('quarantined');
    });

    it('invokes kill switch handlers on ring breaches', async () => {
      const ringScopedClient = AgentMeshClient.create('kill-agent', {
        policyRules: [{ action: '*', effect: 'allow' }],
        execution: {
          agentRing: ExecutionRing.Ring3,
          actionRings: {
            'ops.*': ExecutionRing.Ring1,
          },
          killOnBreach: true,
        },
        killSwitch: {
          enabled: true,
        },
      });

      const seen: string[] = [];
      ringScopedClient.killSwitch?.registerHandler(ringScopedClient.identity.did, async () => {
        seen.push('killed');
      });

      const result = await ringScopedClient.executeWithGovernance('ops.restart');
      expect(seen).toEqual(['killed']);
      expect(result.killSwitchResult?.callbacksExecuted).toBe(1);
    });

    it('can skip quarantine when configured', async () => {
      const ringScopedClient = AgentMeshClient.create('non-quarantine-agent', {
        policyRules: [{ action: '*', effect: 'allow' }],
        execution: {
          agentRing: ExecutionRing.Ring2,
          actionRings: {
            'admin.*': ExecutionRing.Ring0,
          },
          quarantineOnBreach: false,
        },
      });

      const result = await ringScopedClient.executeWithGovernance('admin.shutdown');
      expect(result.decision).toBe('deny');
      expect(result.lifecycleState).toBe('active');
      expect(result.killSwitchResult).toBeUndefined();
    });
  });

  describe('end-to-end governance flow', () => {
    it('maintains audit chain integrity across multiple operations', async () => {
      const actions = ['data.read', 'data.delete', 'data.read', 'unknown.action'];

      for (const action of actions) {
        await client.executeWithGovernance(action);
      }

      expect(client.audit.verify()).toBe(true);
      expect(client.audit.getEntries()).toHaveLength(4);
    });

    it('applies default-deny for unknown actions', async () => {
      const result = await client.executeWithGovernance('unregistered.action');
      expect(result.decision).toBe('deny');
    });
  });
});

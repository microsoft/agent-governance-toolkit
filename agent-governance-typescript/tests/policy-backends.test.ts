// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CedarBackend } from '../src/policy-backends/cedar';
import { OPABackend } from '../src/policy-backends/opa';
import { PolicyEngine } from '../src/policy';

describe('Policy backends', () => {
  it('registers and lists policy backends', () => {
    const engine = new PolicyEngine();
    engine.registerBackend({
      name: 'test-backend',
      evaluateAction: () => 'allow',
    });

    expect(engine.listBackends()).toEqual(['test-backend']);
    engine.clearBackends();
    expect(engine.listBackends()).toEqual([]);
  });

  it('fails closed when a backend denies an allowed action', async () => {
    const engine = new PolicyEngine([{ action: 'data.read', effect: 'allow' }]);
    engine.registerBackend({
      name: 'deny-backend',
      evaluateAction: () => 'deny',
    });

    const result = await engine.evaluateWithBackends('data.read');
    expect(result.effectiveDecision).toBe('deny');
    expect(result.deniedBy).toEqual(['deny-backend']);
  });

  it('fails closed when a backend throws', async () => {
    const engine = new PolicyEngine([{ action: 'data.read', effect: 'allow' }]);
    engine.registerBackend({
      name: 'error-backend',
      evaluateAction: async () => {
        throw new Error('backend unavailable');
      },
    });

    const result = await engine.evaluateWithBackends('data.read');
    expect(result.effectiveDecision).toBe('deny');
    expect(result.backendResults[0].error).toContain('backend unavailable');
  });

  it('merges rich policy results with backends', async () => {
    const engine = new PolicyEngine();
    engine.loadPolicy({
      name: 'allow-read',
      agents: ['*'],
      rules: [{ name: 'allow', condition: "action.type == 'read'", ruleAction: 'allow' }],
      default_action: 'deny',
    });
    engine.registerBackend({
      name: 'allow-backend',
      evaluatePolicy: () => 'allow',
    });

    const result = await engine.evaluatePolicyWithBackends('did:test', {
      action: { type: 'read' },
    });
    expect(result.effectiveDecision).toBe('allow');
    expect(result.effectivePolicyResult?.allowed).toBe(true);
  });

  it('maps OPA responses into backend decisions', async () => {
    const fetchImpl: typeof fetch = jest.fn(async () => ({
      ok: true,
      json: async () => ({ result: true }),
    } as Response));

    const backend = new OPABackend({
      endpoint: 'https://opa.example.com',
      fetchImpl,
    });

    await expect(backend.evaluateAction('data.read', { actor: 'alice' })).resolves.toBe('allow');
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://opa.example.com/v1/data/agentmesh/allow',
      expect.objectContaining({
        method: 'POST',
      }),
    );
  });

  it('does not allow caller context to override OPA action payload fields', async () => {
    const fetchImpl: typeof fetch = jest.fn(async (_input, init) => ({
      ok: true,
      json: async () => {
        const body = JSON.parse(String(init?.body));
        expect(body.input.action).toBe('policy.evaluate');
        expect(body.input.agentDid).toBe('did:test');
        return { result: true };
      },
    } as Response));

    const backend = new OPABackend({
      endpoint: 'https://opa.example.com',
      fetchImpl,
    });

    await expect(backend.evaluatePolicy('did:test', {
      action: 'admin.delete',
      agentDid: 'did:spoofed',
    })).resolves.toBe('allow');
  });

  it('maps Cedar responses into backend decisions', async () => {
    const fetchImpl: typeof fetch = jest.fn(async () => ({
      ok: true,
      json: async () => ({ decision: 'deny' }),
    } as Response));

    const backend = new CedarBackend({
      endpoint: 'https://cedar.example.com/evaluate',
      fetchImpl,
    });

    await expect(backend.evaluatePolicy('did:test', { resource: 'secret' })).resolves.toBe('deny');
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://cedar.example.com/evaluate',
      expect.objectContaining({
        method: 'POST',
      }),
    );
  });

  it('preserves local require_approval decisions when no backend denial occurs', async () => {
    const engine = new PolicyEngine();
    engine.loadPolicy({
      name: 'approval-policy',
      agents: ['*'],
      rules: [{
        name: 'review',
        ruleAction: 'require_approval',
        approvers: ['alice@org.com'],
      }],
    });

    const result = await engine.evaluatePolicyWithBackends('did:test', {});
    expect(result.effectiveDecision).toBe('review');
    expect(result.effectivePolicyResult?.action).toBe('require_approval');
    expect(result.effectivePolicyResult?.approvers).toEqual(['alice@org.com']);
    expect(result.deniedBy).toEqual([]);
  });
});

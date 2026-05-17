// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  PolicyEngine,
  PolicyConflictResolver,
} from '../src/policy';
import {
  ConflictResolutionStrategy,
  PolicyScope,
  Policy,
  PolicyDecisionResult,
} from '../src/types';
import { writeFileSync, unlinkSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('PolicyEngine — Rich Policy API', () => {
  // ── Policy loading ──

  describe('loadPolicy()', () => {
    it('loads a policy document', () => {
      const engine = new PolicyEngine();
      const policy: Policy = {
        name: 'test-policy',
        agents: ['*'],
        rules: [
          { name: 'r1', condition: "action.type == 'read'", ruleAction: 'allow' },
        ],
        default_action: 'deny',
      };
      engine.loadPolicy(policy);
      expect(engine.listPolicies()).toEqual(['test-policy']);
    });

    it('replaces a policy with the same name', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ name: 'p1', agents: ['*'], rules: [] });
      engine.loadPolicy({ name: 'p1', agents: ['*'], rules: [{ name: 'r1', ruleAction: 'allow' }] });
      expect(engine.listPolicies()).toEqual(['p1']);
      expect(engine.getPolicy('p1')!.rules).toHaveLength(1);
    });
  });

  describe('loadYaml()', () => {
    it('parses a YAML policy document', () => {
      const engine = new PolicyEngine();
      const yaml = `
name: yaml-policy
agents: ["*"]
scope: global
default_action: deny
rules:
  - name: allow-reads
    condition: "action.type == 'read'"
    ruleAction: allow
    priority: 10
  - name: deny-exports
    condition: "action.type == 'export'"
    ruleAction: deny
    priority: 20
`;
      const policy = engine.loadYaml(yaml);
      expect(policy.name).toBe('yaml-policy');
      expect(policy.rules).toHaveLength(2);
      expect(engine.listPolicies()).toContain('yaml-policy');
    });
  });

  describe('loadJson()', () => {
    it('parses a JSON policy document', () => {
      const engine = new PolicyEngine();
      const json = JSON.stringify({
        name: 'json-policy',
        agents: ['*'],
        rules: [
          { name: 'r1', condition: "action.type == 'read'", ruleAction: 'allow' },
        ],
      });
      const policy = engine.loadJson(json);
      expect(policy.name).toBe('json-policy');
    });
  });

  describe('removePolicy() / clearPolicies()', () => {
    it('removes a specific policy', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ name: 'p1', agents: ['*'], rules: [] });
      engine.loadPolicy({ name: 'p2', agents: ['*'], rules: [] });
      expect(engine.removePolicy('p1')).toBe(true);
      expect(engine.listPolicies()).toEqual(['p2']);
    });

    it('returns false for unknown policy', () => {
      const engine = new PolicyEngine();
      expect(engine.removePolicy('nonexistent')).toBe(false);
    });

    it('clears all policies', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ name: 'p1', agents: ['*'], rules: [] });
      engine.clearPolicies();
      expect(engine.listPolicies()).toHaveLength(0);
    });
  });

  // ── Expression evaluation ──

  describe('expression evaluation', () => {
    function makeEngine(condition: string, action: string = 'allow'): PolicyEngine {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'test',
        agents: ['*'],
        rules: [{ name: 'r1', condition, ruleAction: action as any }],
        default_action: 'deny',
      });
      return engine;
    }

    function evalResult(engine: PolicyEngine, context: Record<string, unknown>): PolicyDecisionResult {
      return engine.evaluatePolicy('did:agentmesh:test:abc', context);
    }

    it('evaluates string equality', () => {
      const engine = makeEngine("action.type == 'read'");
      expect(evalResult(engine, { action: { type: 'read' } }).allowed).toBe(true);
      expect(evalResult(engine, { action: { type: 'write' } }).allowed).toBe(false);
    });

    it('evaluates numeric equality', () => {
      const engine = makeEngine('count == 5');
      expect(evalResult(engine, { count: 5 }).allowed).toBe(true);
      expect(evalResult(engine, { count: 6 }).allowed).toBe(false);
    });

    it('evaluates boolean equality', () => {
      const engine = makeEngine('data.is_pii == true');
      expect(evalResult(engine, { data: { is_pii: true } }).allowed).toBe(true);
      expect(evalResult(engine, { data: { is_pii: false } }).allowed).toBe(false);
    });

    it('evaluates inequality (!=)', () => {
      const engine = makeEngine("role != 'admin'");
      expect(evalResult(engine, { role: 'user' }).allowed).toBe(true);
      expect(evalResult(engine, { role: 'admin' }).allowed).toBe(false);
    });

    it('evaluates greater than (>)', () => {
      const engine = makeEngine('cost > 100');
      expect(evalResult(engine, { cost: 150 }).allowed).toBe(true);
      expect(evalResult(engine, { cost: 50 }).allowed).toBe(false);
    });

    it('evaluates less than (<)', () => {
      const engine = makeEngine('risk < 0.5');
      expect(evalResult(engine, { risk: 0.3 }).allowed).toBe(true);
      expect(evalResult(engine, { risk: 0.8 }).allowed).toBe(false);
    });

    it('evaluates >= and <=', () => {
      const gte = makeEngine('score >= 80');
      expect(evalResult(gte, { score: 80 }).allowed).toBe(true);
      expect(evalResult(gte, { score: 79 }).allowed).toBe(false);

      const lte = makeEngine('priority <= 3');
      expect(evalResult(lte, { priority: 3 }).allowed).toBe(true);
      expect(evalResult(lte, { priority: 4 }).allowed).toBe(false);
    });

    it('evaluates `in` operator', () => {
      const engine = makeEngine("user.role in ['admin', 'operator']");
      expect(evalResult(engine, { user: { role: 'admin' } }).allowed).toBe(true);
      expect(evalResult(engine, { user: { role: 'operator' } }).allowed).toBe(true);
      expect(evalResult(engine, { user: { role: 'viewer' } }).allowed).toBe(false);
    });

    it('evaluates `not in` operator', () => {
      const engine = makeEngine("env not in ['production', 'staging']");
      expect(evalResult(engine, { env: 'development' }).allowed).toBe(true);
      expect(evalResult(engine, { env: 'production' }).allowed).toBe(false);
    });

    it('evaluates boolean truthy attributes', () => {
      const engine = makeEngine('data.contains_pii');
      expect(evalResult(engine, { data: { contains_pii: true } }).allowed).toBe(true);
      expect(evalResult(engine, { data: { contains_pii: false } }).allowed).toBe(false);
      expect(evalResult(engine, { data: {} }).allowed).toBe(false);
    });

    it('evaluates compound AND', () => {
      const engine = makeEngine("action.type == 'write' and user.role == 'admin'");
      expect(evalResult(engine, { action: { type: 'write' }, user: { role: 'admin' } }).allowed).toBe(true);
      expect(evalResult(engine, { action: { type: 'write' }, user: { role: 'user' } }).allowed).toBe(false);
    });

    it('evaluates compound OR', () => {
      const engine = makeEngine("user.role == 'admin' or user.role == 'superuser'");
      expect(evalResult(engine, { user: { role: 'admin' } }).allowed).toBe(true);
      expect(evalResult(engine, { user: { role: 'superuser' } }).allowed).toBe(true);
      expect(evalResult(engine, { user: { role: 'viewer' } }).allowed).toBe(false);
    });

    it('does not split on ` or ` / ` and ` substrings inside string literals', () => {
      // Before this guard, `String.split(' or ')` on the condition string
      // sliced the literal `'foo or bar'` in half, the resulting fragments
      // never matched any comparison branch, and the rule silently
      // evaluated to deny.
      const orEngine = makeEngine("name == 'foo or bar'");
      expect(evalResult(orEngine, { name: 'foo or bar' }).allowed).toBe(true);
      expect(evalResult(orEngine, { name: 'foo' }).allowed).toBe(false);

      const andEngine = makeEngine("name == 'big and tall'");
      expect(evalResult(andEngine, { name: 'big and tall' }).allowed).toBe(true);
      expect(evalResult(andEngine, { name: 'big' }).allowed).toBe(false);

      // Double-quoted literals get the same treatment.
      const dqEngine = makeEngine('label == "ham or eggs"');
      expect(evalResult(dqEngine, { label: 'ham or eggs' }).allowed).toBe(true);

      // Mixed: a real out-of-quote `and` plus a literal ` or ` inside a string.
      const mixedEngine = makeEngine(
        "name == 'foo or bar' and role == 'admin'",
      );
      expect(
        evalResult(mixedEngine, { name: 'foo or bar', role: 'admin' }).allowed,
      ).toBe(true);
      expect(
        evalResult(mixedEngine, { name: 'foo or bar', role: 'user' }).allowed,
      ).toBe(false);
    });

    it('handles nested dot paths', () => {
      const engine = makeEngine("request.metadata.source == 'internal'");
      expect(evalResult(engine, { request: { metadata: { source: 'internal' } } }).allowed).toBe(true);
      expect(evalResult(engine, { request: { metadata: { source: 'external' } } }).allowed).toBe(false);
    });

    it('returns false for missing nested paths', () => {
      const engine = makeEngine("missing.deep.path == 'value'");
      expect(evalResult(engine, {}).allowed).toBe(false);
    });
  });

  // ── Policy scoping ──

  describe('policy scoping (agent/agents)', () => {
    it('applies when agent DID matches', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'agent-specific',
        agent: 'did:agentmesh:bot:abc',
        rules: [{ name: 'r1', ruleAction: 'allow' }],
      });
      const r1 = engine.evaluatePolicy('did:agentmesh:bot:abc', {});
      expect(r1.allowed).toBe(true);

      const r2 = engine.evaluatePolicy('did:agentmesh:other:xyz', {});
      expect(r2.allowed).toBe(false); // fail closed when no policies apply
    });

    it('applies to agents list', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'multi-agent',
        agents: ['did:agentmesh:a:1', 'did:agentmesh:b:2'],
        rules: [{ name: 'r1', ruleAction: 'deny' }],
      });

      expect(engine.evaluatePolicy('did:agentmesh:a:1', {}).allowed).toBe(false);
      expect(engine.evaluatePolicy('did:agentmesh:b:2', {}).allowed).toBe(false);
      expect(engine.evaluatePolicy('did:agentmesh:c:3', {}).allowed).toBe(false);
    });

    it('wildcard agents applies to all', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'global',
        agents: ['*'],
        rules: [{ name: 'r1', ruleAction: 'deny' }],
      });
      expect(engine.evaluatePolicy('did:agentmesh:any:agent', {}).allowed).toBe(false);
    });
  });

  // ── Default action ──

  describe('default action', () => {
    it('uses default deny when no rules match', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'strict',
        agents: ['*'],
        rules: [{ name: 'r1', condition: "role == 'admin'", ruleAction: 'allow' }],
        default_action: 'deny',
      });
      expect(engine.evaluatePolicy('did:test', { role: 'viewer' }).allowed).toBe(false);
    });

    it('uses default allow when configured', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'permissive',
        agents: ['*'],
        rules: [{ name: 'r1', condition: "action == 'delete'", ruleAction: 'deny' }],
        default_action: 'allow',
      });
      expect(engine.evaluatePolicy('did:test', { action: 'read' }).allowed).toBe(true);
    });
  });

  // ── Rich PolicyDecisionResult ──

  describe('PolicyDecisionResult', () => {
    it('includes matched rule and policy name', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'data-policy',
        agents: ['*'],
        rules: [{ name: 'block-exports', condition: "action.type == 'export'", ruleAction: 'deny', description: 'No exports allowed' }],
      });
      const result = engine.evaluatePolicy('did:test', { action: { type: 'export' } });
      expect(result.allowed).toBe(false);
      expect(result.matchedRule).toBe('block-exports');
      expect(result.policyName).toBe('data-policy');
      expect(result.reason).toBe('No exports allowed');
    });

    it('includes evaluation timing', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'p',
        agents: ['*'],
        rules: [{ name: 'r', ruleAction: 'allow' }],
      });
      const result = engine.evaluatePolicy('did:test', {});
      expect(typeof result.evaluationMs).toBe('number');
      expect(result.evaluationMs!).toBeGreaterThanOrEqual(0);
      expect(result.evaluatedAt).toBeInstanceOf(Date);
    });

    it('includes approvers for require_approval', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'approval-policy',
        agents: ['*'],
        rules: [{
          name: 'need-approval',
          ruleAction: 'require_approval',
          approvers: ['alice@org.com', 'bob@org.com'],
        }],
      });
      const result = engine.evaluatePolicy('did:test', {});
      expect(result.action).toBe('require_approval');
      expect(result.approvers).toEqual(['alice@org.com', 'bob@org.com']);
    });
  });

  // ── Rule priority and enabled ──

  describe('rule priority and enabled', () => {
    it('higher priority rules win (priority-first-match)', () => {
      const engine = new PolicyEngine([], ConflictResolutionStrategy.PriorityFirstMatch);
      engine.loadPolicy({
        name: 'p',
        agents: ['*'],
        rules: [
          { name: 'low', ruleAction: 'deny', priority: 1 },
          { name: 'high', ruleAction: 'allow', priority: 10 },
        ],
      });
      const result = engine.evaluatePolicy('did:test', {});
      expect(result.allowed).toBe(true);
      expect(result.matchedRule).toBe('high');
    });

    it('disabled rules are skipped', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'p',
        agents: ['*'],
        rules: [
          { name: 'disabled', ruleAction: 'allow', enabled: false },
          { name: 'active', ruleAction: 'deny' },
        ],
      });
      const result = engine.evaluatePolicy('did:test', {});
      expect(result.allowed).toBe(false);
      expect(result.matchedRule).toBe('active');
    });
  });

  // ── Rate limiting ──

  describe('rate limiting', () => {
    it('enforces rate limits', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        name: 'rate-limited',
        agents: ['*'],
        rules: [{ name: 'api-call', ruleAction: 'allow', limit: '2/hour' }],
      });

      const r1 = engine.evaluatePolicy('did:test', {});
      expect(r1.allowed).toBe(true);
      expect(r1.rateLimited).toBe(false);

      const r2 = engine.evaluatePolicy('did:test', {});
      expect(r2.allowed).toBe(true);

      // Third call exceeds 2/hour limit
      const r3 = engine.evaluatePolicy('did:test', {});
      expect(r3.allowed).toBe(false);
      expect(r3.rateLimited).toBe(true);
    });
  });
});

// ── Conflict Resolution ──

describe('PolicyConflictResolver', () => {
  const makeCandidates = (): import('../src/types').CandidateDecision[] => [
    { action: 'allow', priority: 5, scope: PolicyScope.Global, policyName: 'p1', ruleName: 'allow-rule', reason: 'allowed', approvers: [] },
    { action: 'deny', priority: 10, scope: PolicyScope.Tenant, policyName: 'p2', ruleName: 'deny-rule', reason: 'denied', approvers: [] },
  ];

  it('deny_overrides: deny always wins', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.DenyOverrides);
    const result = resolver.resolve(makeCandidates());
    expect(result.winningDecision.action).toBe('deny');
    expect(result.conflictDetected).toBe(true);
  });

  it('allow_overrides: allow always wins', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.AllowOverrides);
    const result = resolver.resolve(makeCandidates());
    expect(result.winningDecision.action).toBe('allow');
    expect(result.conflictDetected).toBe(true);
  });

  it('priority_first_match: highest priority wins', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.PriorityFirstMatch);
    const result = resolver.resolve(makeCandidates());
    expect(result.winningDecision.ruleName).toBe('deny-rule');
    expect(result.winningDecision.priority).toBe(10);
  });

  it('most_specific_wins: agent scope > tenant > global', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.MostSpecificWins);
    const candidates = [
      { action: 'allow' as const, priority: 100, scope: PolicyScope.Global, policyName: 'p1', ruleName: 'global-allow', reason: '', approvers: [] },
      { action: 'deny' as const, priority: 1, scope: PolicyScope.Agent, policyName: 'p2', ruleName: 'agent-deny', reason: '', approvers: [] },
    ];
    const result = resolver.resolve(candidates);
    expect(result.winningDecision.ruleName).toBe('agent-deny');
  });

  it('single candidate has no conflict', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.DenyOverrides);
    const result = resolver.resolve([makeCandidates()[0]]);
    expect(result.conflictDetected).toBe(false);
    expect(result.candidatesEvaluated).toBe(1);
  });

  it('throws on zero candidates', () => {
    const resolver = new PolicyConflictResolver(ConflictResolutionStrategy.DenyOverrides);
    expect(() => resolver.resolve([])).toThrow('Cannot resolve conflict with zero candidates');
  });
});

// ── Full YAML policy document round-trip ──

describe('YAML policy document loading', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'policy-parity-'));
  });

  it('loads a full policy document from YAML', () => {
    const yamlContent = `
apiVersion: governance.toolkit/v1
name: data-governance
description: Controls data operations
agents:
  - "*"
scope: global
default_action: deny
rules:
  - name: allow-reads
    condition: "action.type == 'read'"
    ruleAction: allow
    priority: 10
  - name: block-pii-export
    condition: "action.type == 'export' and data.contains_pii"
    ruleAction: deny
    priority: 20
    description: PII data cannot be exported
  - name: admin-bypass
    condition: "user.role == 'admin'"
    ruleAction: allow
    priority: 100
`;
    const engine = new PolicyEngine();
    const policy = engine.loadYaml(yamlContent);

    expect(policy.name).toBe('data-governance');
    expect(policy.apiVersion).toBe('governance.toolkit/v1');
    expect(policy.rules).toHaveLength(3);

    // Test evaluation
    const r1 = engine.evaluatePolicy('did:test', { action: { type: 'read' }, user: { role: 'viewer' } });
    expect(r1.allowed).toBe(true);

    const r2 = engine.evaluatePolicy('did:test', {
      action: { type: 'export' },
      data: { contains_pii: true },
      user: { role: 'viewer' },
    });
    expect(r2.allowed).toBe(false);
    expect(r2.matchedRule).toBe('block-pii-export');

    // Admin bypass has highest priority
    const r3 = engine.evaluatePolicy('did:test', {
      action: { type: 'export' },
      data: { contains_pii: true },
      user: { role: 'admin' },
    });
    expect(r3.allowed).toBe(true);
    expect(r3.matchedRule).toBe('admin-bypass');
  });
});

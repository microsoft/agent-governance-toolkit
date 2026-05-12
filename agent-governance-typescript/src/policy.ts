// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { readFileSync } from 'fs';
import {
  PolicyRule,
  Policy,
  PolicyAction,
  PolicyDecisionResult,
  CandidateDecision,
  BackendDecision,
  BackendEvaluationOutcome,
  ExternalPolicyBackend,
  PolicyBackendEvaluationResult,
  ResolutionResult,
  ConflictResolutionStrategy,
  PolicyScope,
  LegacyPolicyDecision,
} from './types';

export type PolicyDecision = LegacyPolicyDecision;

// ΓöÇΓöÇ Conflict Resolution ΓöÇΓöÇ

const SCOPE_SPECIFICITY: Record<PolicyScope, number> = {
  [PolicyScope.Global]: 0,
  [PolicyScope.Tenant]: 1,
  [PolicyScope.Agent]: 2,
};

/**
 * Resolves conflicts between competing policy candidate decisions.
 */
export class PolicyConflictResolver {
  constructor(readonly strategy: ConflictResolutionStrategy) {}

  resolve(candidates: CandidateDecision[]): ResolutionResult {
    if (candidates.length === 0) {
      throw new Error('Cannot resolve conflict with zero candidates');
    }
    if (candidates.length === 1) {
      return {
        winningDecision: candidates[0],
        strategyUsed: this.strategy,
        candidatesEvaluated: 1,
        conflictDetected: false,
        resolutionTrace: [`Single candidate: ${candidates[0].ruleName} ΓåÆ ${candidates[0].action}`],
      };
    }

    const actions = new Set(candidates.map((c) => c.action));
    const conflictDetected = actions.has('allow') && actions.has('deny');

    const dispatch: Record<
      ConflictResolutionStrategy,
      (cs: CandidateDecision[]) => { winner: CandidateDecision; trace: string[] }
    > = {
      [ConflictResolutionStrategy.DenyOverrides]: (cs) => this.denyOverrides(cs),
      [ConflictResolutionStrategy.AllowOverrides]: (cs) => this.allowOverrides(cs),
      [ConflictResolutionStrategy.PriorityFirstMatch]: (cs) => this.priorityFirstMatch(cs),
      [ConflictResolutionStrategy.MostSpecificWins]: (cs) => this.mostSpecificWins(cs),
    };

    const { winner, trace } = dispatch[this.strategy](candidates);
    return {
      winningDecision: winner,
      strategyUsed: this.strategy,
      candidatesEvaluated: candidates.length,
      conflictDetected,
      resolutionTrace: trace,
    };
  }

  private denyOverrides(candidates: CandidateDecision[]) {
    const denies = candidates.filter((c) => c.action === 'deny');
    if (denies.length > 0) {
      denies.sort((a, b) => b.priority - a.priority);
      return {
        winner: denies[0],
        trace: [
          `DENY_OVERRIDES: ${denies.length} deny rule(s) found`,
          `Winner: ${denies[0].ruleName} (priority=${denies[0].priority})`,
        ],
      };
    }
    const sorted = [...candidates].sort((a, b) => b.priority - a.priority);
    return {
      winner: sorted[0],
      trace: ['DENY_OVERRIDES: no deny rules, selecting highest-priority allow'],
    };
  }

  private allowOverrides(candidates: CandidateDecision[]) {
    const allows = candidates.filter((c) => c.action === 'allow');
    if (allows.length > 0) {
      allows.sort((a, b) => b.priority - a.priority);
      return {
        winner: allows[0],
        trace: [
          `ALLOW_OVERRIDES: ${allows.length} allow rule(s) found`,
          `Winner: ${allows[0].ruleName} (priority=${allows[0].priority})`,
        ],
      };
    }
    const sorted = [...candidates].sort((a, b) => b.priority - a.priority);
    return {
      winner: sorted[0],
      trace: ['ALLOW_OVERRIDES: no allow rules, selecting highest-priority deny'],
    };
  }

  private priorityFirstMatch(candidates: CandidateDecision[]) {
    const sorted = [...candidates].sort((a, b) => b.priority - a.priority);
    return {
      winner: sorted[0],
      trace: [
        `PRIORITY_FIRST_MATCH: ${candidates.length} candidates`,
        `Winner: ${sorted[0].ruleName} (priority=${sorted[0].priority}, action=${sorted[0].action})`,
      ],
    };
  }

  private mostSpecificWins(candidates: CandidateDecision[]) {
    const sorted = [...candidates].sort((a, b) => {
      const specDiff =
        (SCOPE_SPECIFICITY[b.scope] ?? 0) - (SCOPE_SPECIFICITY[a.scope] ?? 0);
      if (specDiff !== 0) return specDiff;
      return b.priority - a.priority;
    });
    return {
      winner: sorted[0],
      trace: [
        `MOST_SPECIFIC_WINS: ${candidates.length} candidates`,
        `Winner: ${sorted[0].ruleName} (scope=${sorted[0].scope}, priority=${sorted[0].priority})`,
      ],
    };
  }
}

// ΓöÇΓöÇ Expression Evaluator ΓöÇΓöÇ

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current === 'object') {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return current;
}

/**
 * Split `expr` on the literal separator `sep` only at positions that are
 * outside of single- or double-quoted string literals. A naive
 * `String.split(' or ')` mis-splits expressions like
 * `name == 'foo or bar'` because the operator substring also appears inside
 * the string literal; this helper walks the expression once, tracking quote
 * state, and only treats separator occurrences outside quotes as boundaries.
 * If no out-of-quote occurrence is found, the result has length 1 and the
 * caller falls through to the comparison-operator branches.
 */
function splitOutsideQuotes(expr: string, sep: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i <= expr.length - sep.length; i++) {
    const ch = expr[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (!inSingle && !inDouble && expr.startsWith(sep, i)) {
      parts.push(expr.slice(start, i));
      start = i + sep.length;
      i += sep.length - 1;
    }
  }
  parts.push(expr.slice(start));
  return parts;
}

/**
 * Evaluate a condition expression string against a context dictionary.
 * Supports: equality, inequality, numeric comparisons, `in` operator,
 * boolean attributes, and compound `and`/`or`.
 */
function evaluateExpression(expr: string, context: Record<string, unknown>): boolean {
  const trimmed = expr.trim();

  // OR conditions (lowest precedence) — only split on out-of-quote separators
  // so `name == 'foo or bar'` is not mis-tokenised.
  const orParts = splitOutsideQuotes(trimmed, ' or ');
  if (orParts.length > 1) {
    return orParts.some((p) => evaluateExpression(p.trim(), context));
  }

  // AND conditions — same out-of-quote split.
  const andParts = splitOutsideQuotes(trimmed, ' and ');
  if (andParts.length > 1) {
    return andParts.every((p) => evaluateExpression(p.trim(), context));
  }

  // NOT IN: path not in ['a', 'b']
  const notInMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s+not\s+in\s+\[([^\]]*)\]$/,
  );
  if (notInMatch) {
    const [, path, listStr] = notInMatch;
    const actual = getNestedValue(context, path);
    const items = parseListLiteral(listStr);
    return !items.includes(String(actual));
  }

  // IN: path in ['a', 'b']
  const inMatch = trimmed.match(/^(\w+(?:\.\w+)*)\s+in\s+\[([^\]]*)\]$/);
  if (inMatch) {
    const [, path, listStr] = inMatch;
    const actual = getNestedValue(context, path);
    const items = parseListLiteral(listStr);
    return items.includes(String(actual));
  }

  // NOT EQUALS: path != 'value' or path != number
  const neqStrMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*!=\s*['"]([^'"]*)['"]\s*$/,
  );
  if (neqStrMatch) {
    const [, path, value] = neqStrMatch;
    return getNestedValue(context, path) !== value;
  }
  const neqNumMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*!=\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (neqNumMatch) {
    const [, path, numStr] = neqNumMatch;
    return Number(getNestedValue(context, path)) !== Number(numStr);
  }

  // EQUALS: path == 'value'
  const eqStrMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*==\s*['"]([^'"]*)['"]\s*$/,
  );
  if (eqStrMatch) {
    const [, path, value] = eqStrMatch;
    return getNestedValue(context, path) === value;
  }

  // EQUALS: path == number
  const eqNumMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*==\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (eqNumMatch) {
    const [, path, numStr] = eqNumMatch;
    return Number(getNestedValue(context, path)) === Number(numStr);
  }

  // EQUALS: path == true/false
  const eqBoolMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*==\s*(true|false)\s*$/,
  );
  if (eqBoolMatch) {
    const [, path, boolStr] = eqBoolMatch;
    return getNestedValue(context, path) === (boolStr === 'true');
  }

  // GREATER THAN OR EQUAL: path >= number
  const gteMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*>=\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (gteMatch) {
    const [, path, numStr] = gteMatch;
    return Number(getNestedValue(context, path)) >= Number(numStr);
  }

  // LESS THAN OR EQUAL: path <= number
  const lteMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*<=\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (lteMatch) {
    const [, path, numStr] = lteMatch;
    return Number(getNestedValue(context, path)) <= Number(numStr);
  }

  // GREATER THAN: path > number
  const gtMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*>\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (gtMatch) {
    const [, path, numStr] = gtMatch;
    return Number(getNestedValue(context, path)) > Number(numStr);
  }

  // LESS THAN: path < number
  const ltMatch = trimmed.match(
    /^(\w+(?:\.\w+)*)\s*<\s*(\d+(?:\.\d+)?)\s*$/,
  );
  if (ltMatch) {
    const [, path, numStr] = ltMatch;
    return Number(getNestedValue(context, path)) < Number(numStr);
  }

  // BOOLEAN attribute: just a path (truthy check)
  const boolAttrMatch = trimmed.match(/^(\w+(?:\.\w+)*)$/);
  if (boolAttrMatch) {
    const path = boolAttrMatch[1];
    return Boolean(getNestedValue(context, path));
  }

  return false;
}

function parseListLiteral(s: string): string[] {
  return s
    .split(',')
    .map((item) => item.trim().replace(/^['"]|['"]$/g, ''))
    .filter((item) => item.length > 0);
}

// ΓöÇΓöÇ Rate Limiting ΓöÇΓöÇ

interface RateLimitState {
  count: number;
  resetAt: number; // epoch ms
}

function parseLimit(limit: string): { count: number; periodMs: number } {
  const parts = limit.split('/');
  const count = parseInt(parts[0], 10);
  const periodMap: Record<string, number> = {
    second: 1_000,
    minute: 60_000,
    hour: 3_600_000,
    day: 86_400_000,
  };
  const periodMs = periodMap[parts[1]] ?? 3_600_000;
  return { count, periodMs };
}

// ΓöÇΓöÇ Policy Engine ΓöÇΓöÇ

/**
 * Declarative policy engine with full parity to the Python/NET SDK.
 *
 * Features:
 * - Rich policy document model with apiVersion, scope, default_action
 * - Expression-based condition evaluation (equality, comparison, in, and/or)
 * - Configurable conflict resolution (deny-overrides, allow-overrides, priority-first-match, most-specific-wins)
 * - Rate limiting support
 * - Approval workflows
 * - Backward-compatible with v0.1 flat rules
 */
export class PolicyEngine {
  private _policies: Map<string, Policy> = new Map();
  private _rateLimits: Map<string, RateLimitState> = new Map();
  private _resolver: PolicyConflictResolver;
  private _backends: ExternalPolicyBackend[] = [];

  /** Legacy flat rules for backward compatibility. */
  private _legacyRules: PolicyRule[] = [];

  constructor(rules?: PolicyRule[], conflictStrategy?: ConflictResolutionStrategy) {
    if (rules) {
      this._legacyRules = [...rules];
    }
    this._resolver = new PolicyConflictResolver(
      conflictStrategy ?? ConflictResolutionStrategy.PriorityFirstMatch,
    );
  }

  // ΓöÇΓöÇ Rich Policy API ΓöÇΓöÇ

  /** Load a Policy document into the engine. */
  loadPolicy(policy: Policy): void {
    this._policies.set(policy.name, policy);
  }

  /** Parse and load a YAML string as a Policy document. */
  loadYaml(yamlContent: string): Policy {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const yaml = require('js-yaml');
    const data = yaml.load(yamlContent) as Record<string, unknown>;
    const policy = dataToPolicy(data);
    this.loadPolicy(policy);
    return policy;
  }

  /** Parse and load a JSON string as a Policy document. */
  loadJson(jsonContent: string): Policy {
    const data = JSON.parse(jsonContent) as Record<string, unknown>;
    const policy = dataToPolicy(data);
    this.loadPolicy(policy);
    return policy;
  }

  /** Get a loaded policy by name. */
  getPolicy(name: string): Policy | undefined {
    return this._policies.get(name);
  }

  /** List all loaded policy names. */
  listPolicies(): string[] {
    return [...this._policies.keys()];
  }

  /** Remove a policy by name. Returns true if found and removed. */
  removePolicy(name: string): boolean {
    return this._policies.delete(name);
  }

  /** Clear all loaded policies. */
  clearPolicies(): void {
    this._policies.clear();
    this._rateLimits.clear();
  }

  registerBackend(backend: ExternalPolicyBackend): void {
    this._backends.push(backend);
  }

  listBackends(): string[] {
    return this._backends.map((backend) => backend.name);
  }

  clearBackends(): void {
    this._backends = [];
  }

  /**
   * Evaluate all applicable policies for an agent action.
   * Returns a rich PolicyDecisionResult with matched rule, timing, etc.
   */
  evaluatePolicy(agentDid: string, context: Record<string, unknown>): PolicyDecisionResult {
    const start = performance.now();

    const applicable = [...this._policies.values()].filter((p) =>
      policyAppliesTo(p, agentDid),
    );

    if (applicable.length > 0) {
      const candidates: CandidateDecision[] = [];
      for (const policy of applicable) {
        let scope: PolicyScope;
        try {
          scope = policy.scope as PolicyScope;
          if (!Object.values(PolicyScope).includes(scope)) scope = PolicyScope.Global;
        } catch {
          scope = PolicyScope.Global;
        }

        for (const rule of policy.rules) {
          if (rule.enabled === false) continue;
          const ruleAction = rule.ruleAction ?? (rule.effect as PolicyAction | undefined) ?? 'deny';
          if (evaluateRuleCondition(rule, context)) {
            candidates.push({
              action: ruleAction,
              priority: rule.priority ?? 0,
              scope,
              policyName: policy.name,
              ruleName: rule.name ?? 'unnamed',
              reason: rule.description ?? `Rule ${rule.name ?? 'unnamed'} matched`,
              approvers: rule.approvers ?? [],
            });
          }
        }
      }

      if (candidates.length > 0) {
        const result = this._resolver.resolve(candidates);
        const winner = result.winningDecision;
        const elapsed = performance.now() - start;

        // Check rate limiting
        const matchedRule = this.findRule(winner.policyName, winner.ruleName);
        if (matchedRule?.limit) {
          if (this.isRateLimited(matchedRule)) {
            return {
              allowed: false,
              action: 'deny',
              matchedRule: matchedRule.name,
              policyName: winner.policyName,
              reason: `Rate limited: ${matchedRule.limit}`,
              approvers: [],
              rateLimited: true,
              evaluatedAt: new Date(),
              evaluationMs: elapsed,
            };
          }
          this.incrementRateLimit(matchedRule);
        }

        return {
          allowed: winner.action === 'allow',
          action: winner.action,
          matchedRule: winner.ruleName,
          policyName: winner.policyName,
          reason: winner.reason,
          approvers: winner.action === 'require_approval' ? winner.approvers : [],
          rateLimited: false,
          evaluatedAt: new Date(),
          evaluationMs: elapsed,
        };
      }
    }

    // No rules matched - fail closed.
    const defaultAction =
      applicable.length > 0 ? (applicable[0].default_action ?? 'deny') : 'deny';
    const elapsed = performance.now() - start;
    return {
      allowed: defaultAction === 'allow',
      action: defaultAction,
      reason: 'No matching rules, using default',
      approvers: [],
      rateLimited: false,
      evaluatedAt: new Date(),
      evaluationMs: elapsed,
    };
  }

  async evaluateWithBackends(
    action: string,
    context: Record<string, unknown> = {},
  ): Promise<PolicyBackendEvaluationResult> {
    const localDecision = this.evaluate(action, context);
    if (localDecision === 'deny') {
      return {
        localDecision,
        backendResults: [],
        effectiveDecision: 'deny',
        deniedBy: ['local'],
      };
    }

    const backendResults = await Promise.all(
      this._backends.map((backend) => this.runActionBackend(backend, action, context)),
    );

    const effectiveDecision = resolveEffectiveDecision(localDecision, backendResults);
    const deniedBy = collectDeniedBy(backendResults, effectiveDecision === 'deny');

    return {
      localDecision,
      backendResults,
      effectiveDecision,
      deniedBy,
    };
  }

  async evaluatePolicyWithBackends(
    agentDid: string,
    context: Record<string, unknown>,
  ): Promise<PolicyBackendEvaluationResult> {
    const localDecision = this.evaluatePolicy(agentDid, context);
    if (!localDecision.allowed) {
      const effectiveDecision = localDecision.action === 'require_approval' ? 'review' : 'deny';
      return {
        localDecision,
        backendResults: [],
        effectiveDecision,
        effectivePolicyResult: localDecision,
        deniedBy: effectiveDecision === 'deny' ? ['local'] : [],
      };
    }

    const backendResults = await Promise.all(
      this._backends.map((backend) => this.runPolicyBackend(backend, agentDid, context)),
    );

    const effectiveDecision = resolveEffectiveDecision('allow', backendResults);
    const deniedBy = collectDeniedBy(backendResults, effectiveDecision === 'deny');

    let effectivePolicyResult = localDecision;
    if (effectiveDecision === 'deny') {
      effectivePolicyResult = {
        ...localDecision,
        allowed: false,
        action: 'deny',
        reason: `Denied by policy backend: ${deniedBy.filter((name) => name !== 'local').join(', ')}`,
      };
    } else if (effectiveDecision === 'review') {
      effectivePolicyResult = {
        ...localDecision,
        allowed: false,
        action: 'require_approval',
        reason: 'Review required by policy backend',
      };
    }

    return {
      localDecision,
      backendResults,
      effectiveDecision,
      effectivePolicyResult,
      deniedBy,
    };
  }

  // ΓöÇΓöÇ Legacy v0.1 API (backward compatible) ΓöÇΓöÇ

  /** Load policy rules from a YAML file (legacy flat format). */
  async loadFromYAML(yamlPath: string): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const yaml = require('js-yaml');
    const content = readFileSync(yamlPath, 'utf-8');
    const doc = yaml.load(content) as { rules?: PolicyRule[] };
    if (doc?.rules && Array.isArray(doc.rules)) {
      this._legacyRules.push(...doc.rules);
    }
  }

  /**
   * Evaluate using legacy flat rules (v0.1 compatible).
   * First match wins; default is 'deny'.
   */
  evaluate(action: string, context: Record<string, unknown> = {}): PolicyDecision {
    for (const rule of this._legacyRules) {
      if (
        this.matchAction(rule.action ?? '', action) &&
        this.matchLegacyConditions(
          (rule.condition ?? rule.conditions) as Record<string, unknown> | undefined,
          context,
        )
      ) {
        return (rule.effect ?? 'deny') as PolicyDecision;
      }
    }
    return 'deny';
  }

  /** Append a legacy flat rule. */
  addRule(rule: PolicyRule): void {
    this._legacyRules.push(rule);
  }

  /** Return a snapshot of legacy flat rules. */
  getRules(): readonly PolicyRule[] {
    return [...this._legacyRules];
  }

  // ΓöÇΓöÇ Private helpers ΓöÇΓöÇ

  private matchAction(pattern: string, action: string): boolean {
    if (pattern === '*') return true;
    if (pattern.endsWith('.*')) {
      const prefix = pattern.slice(0, -2);
      return action === prefix || action.startsWith(prefix + '.');
    }
    return pattern === action;
  }

  private matchLegacyConditions(
    conditions: Record<string, unknown> | undefined,
    context: Record<string, unknown>,
  ): boolean {
    if (!conditions) return true;
    for (const [key, expected] of Object.entries(conditions)) {
      const actual = context[key];
      if (actual !== expected) return false;
    }
    return true;
  }

  private findRule(policyName: string, ruleName: string): PolicyRule | undefined {
    const policy = this._policies.get(policyName);
    if (!policy) return undefined;
    return policy.rules.find((r) => r.name === ruleName);
  }

  private isRateLimited(rule: PolicyRule): boolean {
    if (!rule.limit || !rule.name) return false;
    const state = this._rateLimits.get(rule.name);
    if (!state) return false;
    if (Date.now() > state.resetAt) {
      this._rateLimits.delete(rule.name);
      return false;
    }
    const { count } = parseLimit(rule.limit);
    return state.count >= count;
  }

  private incrementRateLimit(rule: PolicyRule): void {
    if (!rule.limit || !rule.name) return;
    let state = this._rateLimits.get(rule.name);
    if (!state) {
      const { periodMs } = parseLimit(rule.limit);
      state = { count: 0, resetAt: Date.now() + periodMs };
      this._rateLimits.set(rule.name, state);
    }
    state.count++;
  }

  private async runActionBackend(
    backend: ExternalPolicyBackend,
    action: string,
    context: Record<string, unknown>,
  ): Promise<BackendEvaluationOutcome> {
    if (!backend.evaluateAction) {
      return {
        backend: backend.name,
        decision: 'allow',
        reason: 'No action evaluator registered',
      };
    }

    try {
      const result = await backend.evaluateAction(action, context);
      return normalizeBackendOutcome(backend.name, result);
    } catch (error) {
      return {
        backend: backend.name,
        decision: 'deny',
        error: error instanceof Error ? error.message : 'Unknown backend error',
      };
    }
  }

  private async runPolicyBackend(
    backend: ExternalPolicyBackend,
    agentDid: string,
    context: Record<string, unknown>,
  ): Promise<BackendEvaluationOutcome> {
    if (!backend.evaluatePolicy) {
      return {
        backend: backend.name,
        decision: 'allow',
        reason: 'No policy evaluator registered',
      };
    }

    try {
      const result = await backend.evaluatePolicy(agentDid, context);
      return normalizeBackendOutcome(backend.name, result);
    } catch (error) {
      return {
        backend: backend.name,
        decision: 'deny',
        error: error instanceof Error ? error.message : 'Unknown backend error',
      };
    }
  }
}

// ΓöÇΓöÇ Helpers ΓöÇΓöÇ

function policyAppliesTo(policy: Policy, agentDid: string): boolean {
  if (policy.agent && policy.agent === agentDid) return true;
  if (policy.agents) {
    if (policy.agents.includes(agentDid)) return true;
    if (policy.agents.includes('*')) return true;
  }
  // If no agent/agents specified, policy applies to all
  if (!policy.agent && (!policy.agents || policy.agents.length === 0)) return true;
  return false;
}

function evaluateRuleCondition(rule: PolicyRule, context: Record<string, unknown>): boolean {
  if (!rule.condition) return true;

  // String expression (rich policy format)
  if (typeof rule.condition === 'string') {
    try {
      return evaluateExpression(rule.condition, context);
    } catch {
      return false;
    }
  }

  // Legacy flat conditions object
  if (typeof rule.condition === 'object') {
    for (const [key, expected] of Object.entries(rule.condition)) {
      if (context[key] !== expected) return false;
    }
    return true;
  }

  return true;
}

function dataToPolicy(data: Record<string, unknown>): Policy {
  const rules: PolicyRule[] = [];
  const rawRules = data.rules as Record<string, unknown>[] | undefined;
  if (rawRules && Array.isArray(rawRules)) {
    for (const r of rawRules) {
      rules.push({
        name: r.name as string | undefined,
        description: r.description as string | undefined,
        condition: r.condition as string | Record<string, unknown> | undefined,
        action: r.action as string | undefined,
        effect: r.effect as LegacyPolicyDecision | undefined,
        ruleAction: r.ruleAction as PolicyAction | undefined,
        limit: r.limit as string | undefined,
        approvers: r.approvers as string[] | undefined,
        priority: r.priority as number | undefined,
        enabled: r.enabled as boolean | undefined,
        surfaces: r.surfaces as import('./types').GovernanceSurface[] | undefined,
      });
    }
  }

  return {
    apiVersion: (data.apiVersion as string) ?? 'governance.toolkit/v1',
    version: data.version as string | undefined,
    name: data.name as string,
    description: data.description as string | undefined,
    agent: data.agent as string | undefined,
    agents: data.agents as string[] | undefined,
    scope: (data.scope as string) ?? 'global',
    rules,
    default_action: (data.default_action as 'allow' | 'deny') ?? 'deny',
  };
}

function normalizeBackendOutcome(
  backendName: string,
  result: BackendDecision | BackendEvaluationOutcome | PolicyDecisionResult,
): BackendEvaluationOutcome {
  if (typeof result === 'string') {
    return {
      backend: backendName,
      decision: result,
    };
  }

  if ('backend' in result && 'decision' in result) {
    return {
      backend: result.backend || backendName,
      decision: result.decision,
      reason: result.reason,
      error: result.error,
    };
  }

  return {
    backend: backendName,
    decision: result.allowed ? 'allow' : 'deny',
    reason: result.reason,
  };
}

function resolveEffectiveDecision(
  localDecision: LegacyPolicyDecision,
  backendResults: BackendEvaluationOutcome[],
): LegacyPolicyDecision {
  if (localDecision === 'deny') {
    return 'deny';
  }

  if (backendResults.some((result) => result.decision === 'deny' || result.error)) {
    return 'deny';
  }

  if (localDecision === 'review' || backendResults.some((result) => result.decision === 'review')) {
    return 'review';
  }

  return 'allow';
}

function collectDeniedBy(
  backendResults: BackendEvaluationOutcome[],
  includeBackends: boolean,
): string[] {
  if (!includeBackends) {
    return [];
  }

  return backendResults
    .filter((result) => result.decision === 'deny' || result.error)
    .map((result) => result.backend);
}

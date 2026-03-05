// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { readFileSync } from 'fs';
import { PolicyRule } from './types';

export type PolicyDecision = 'allow' | 'deny' | 'review';

/**
 * Rule-based policy engine supporting action matching and conditional evaluation.
 */
export class PolicyEngine {
  private rules: PolicyRule[] = [];

  constructor(rules?: PolicyRule[]) {
    if (rules) {
      this.rules = [...rules];
    }
  }

  /** Load policy rules from a YAML file. */
  async loadFromYAML(yamlPath: string): Promise<void> {
    // Dynamic import so js-yaml remains an optional peer dep at runtime
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const yaml = require('js-yaml');
    const content = readFileSync(yamlPath, 'utf-8');
    const doc = yaml.load(content) as { rules?: PolicyRule[] };
    if (doc?.rules && Array.isArray(doc.rules)) {
      this.rules.push(...doc.rules);
    }
  }

  /**
   * Evaluate an action against loaded rules.
   *
   * Rules are evaluated in order; the first match wins.
   * If no rule matches the default decision is 'deny'.
   */
  evaluate(action: string, context: Record<string, unknown> = {}): PolicyDecision {
    for (const rule of this.rules) {
      if (this.matchAction(rule.action, action) && this.matchConditions(rule.conditions, context)) {
        return rule.effect;
      }
    }
    return 'deny'; // default-deny
  }

  /** Append a rule to the policy set. */
  addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  /** Return a snapshot of the current rules. */
  getRules(): readonly PolicyRule[] {
    return [...this.rules];
  }

  // ── Private helpers ──

  private matchAction(pattern: string, action: string): boolean {
    if (pattern === '*') return true;
    if (pattern.endsWith('.*')) {
      const prefix = pattern.slice(0, -2);
      return action === prefix || action.startsWith(prefix + '.');
    }
    return pattern === action;
  }

  private matchConditions(
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
}

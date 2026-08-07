// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Aggregation evaluation for Context Accumulation Governance.
 *
 * Applies organization-authored rules over combinations of accumulated labels,
 * plus a monotone backstop so combinations not covered by a rule escalate for
 * review rather than passing silently.
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/context_aggregation.py.
 * Refs #3084.
 */

import { DataClassification } from './data-classification';
import type { ContextEnvelope } from './context-envelope';

/** One organization-authored rule over a label combination. */
export interface AggregationRule {
  readonly name: string;
  readonly allLabels: ReadonlySet<string>;
  readonly setsSensitivity: DataClassification;
  readonly addsRestrictions: ReadonlySet<string>;
}

export function makeAggregationRule(
  opts: Pick<AggregationRule, 'name' | 'setsSensitivity'> & {
    allLabels: Iterable<string>;
    addsRestrictions?: Iterable<string>;
  },
): AggregationRule {
  return {
    name: opts.name,
    allLabels: new Set(opts.allLabels),
    setsSensitivity: opts.setsSensitivity,
    addsRestrictions: new Set(opts.addsRestrictions ?? []),
  };
}

/** An ordered collection of aggregation rules. */
export interface AggregationRuleSet {
  readonly rules: readonly AggregationRule[];
}

/** Outcome of evaluating an envelope against a rule set. */
export interface AggregationResult {
  readonly aggregateSensitivity: DataClassification;
  readonly restrictions: ReadonlySet<string>;
  readonly escalate: boolean;
  readonly rulesApplied: readonly string[];
}

/** Evaluate env against ruleset and apply the monotone backstop.
 * Escalation fires when no rule governs the envelope yet it has accumulated
 * at least n_category_threshold distinct labels. */
export function evaluateAggregation(
  env: ContextEnvelope,
  ruleset: AggregationRuleSet,
  nCategoryThreshold: number,
): AggregationResult {
  let sensitivity = env.aggregateSensitivity;
  const restrictions = new Set(env.restrictions);
  const applied: string[] = [];

  for (const rule of ruleset.rules) {
    const allPresent = [...rule.allLabels].every((l) => env.labels.has(l));
    if (allPresent) {
      sensitivity = Math.max(sensitivity, rule.setsSensitivity) as DataClassification;
      for (const r of rule.addsRestrictions) restrictions.add(r);
      applied.push(rule.name);
    }
  }

  const escalate = applied.length === 0 && env.labels.size >= nCategoryThreshold;
  return {
    aggregateSensitivity: sensitivity,
    restrictions,
    escalate,
    rulesApplied: applied,
  };
}

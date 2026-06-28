// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Post-execution accumulation and decision integration for Context Accumulation Governance.
 *
 * Sensitivity accumulates from the actual labels an action produced (result_labels),
 * never from a projected output that has not run yet. After folding, the next action
 * is gated against the accumulated envelope.
 *
 * `constrain` is realized as allow-with-obligations and collapses to a concrete
 * PolicyAction via toContextPolicyAction, which fails closed on a path that cannot
 * carry obligations.
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/context_accumulation.py.
 * Refs #3084.
 */

import { DataClassification } from './data-classification';
import { type AggregationRuleSet, evaluateAggregation } from './context-aggregation';
import { type ContextEnvelope, applyRestrictions, fold } from './context-envelope';
import { type ObligationSet, allSatisfied, makeObligationSet } from './obligations';
import type { PolicyAction } from './types';

/** Governance-level outcome of a context-aware decision. */
export type ContextOutcome = 'allow' | 'constrain' | 'deny' | 'escalate';

/** A context-aware decision plus any obligations it carries. */
export interface ContextDecision {
  readonly outcome: ContextOutcome;
  readonly obligations: ObligationSet;
  readonly aggregateSensitivity: DataClassification;
  readonly reason: string;
}

// Action token -> the restriction that, when present, gates it.
const RESTRICTED_ACTIONS: Record<string, string> = {
  export: 'no_external_export',
  delegate: 'no_external_delegation',
  memory_write: 'no_memory_write',
};

/** Fold an action's actual result into env and re-run aggregation.
 * Runs AFTER the action executes (post-execution accumulation). */
export function accumulate(
  env: ContextEnvelope,
  resultLabels: Iterable<string>,
  resultSensitivity: DataClassification,
  ruleset: AggregationRuleSet,
  nCategoryThreshold: number,
): ContextEnvelope {
  const folded = fold(env, resultLabels, resultSensitivity);
  const agg = evaluateAggregation(folded, ruleset, nCategoryThreshold);
  const raised: ContextEnvelope = { ...folded, aggregateSensitivity: agg.aggregateSensitivity };
  return applyRestrictions(raised, agg.restrictions);
}

/** Gate action against the already-accumulated env. */
export function decideNext(
  env: ContextEnvelope,
  action: string,
  ruleset: AggregationRuleSet,
  nCategoryThreshold: number,
  restrictedFloor: DataClassification = DataClassification.RESTRICTED,
): ContextDecision {
  const agg = evaluateAggregation(env, ruleset, nCategoryThreshold);

  if (agg.escalate) {
    return {
      outcome: 'escalate',
      obligations: makeObligationSet({ resultLabels: env.labels }),
      aggregateSensitivity: agg.aggregateSensitivity,
      reason: 'aggregation threshold crossed with no governing rule',
    };
  }

  const gating = RESTRICTED_ACTIONS[action];
  const restrictionPresent = gating !== undefined && env.restrictions.has(gating);
  const floorTriggered = gating !== undefined && agg.aggregateSensitivity >= restrictedFloor;

  if (restrictionPresent || floorTriggered) {
    const obligations: ObligationSet = {
      obligations: [...env.restrictions]
        .sort()
        .map((r) => ({ key: r, satisfied: false })),
      resultLabels: env.labels,
    };
    const reason = restrictionPresent
      ? `action '${action}' restricted by '${gating}'`
      : `action '${action}' gated by sensitivity floor`;
    return {
      outcome: 'constrain',
      obligations,
      aggregateSensitivity: agg.aggregateSensitivity,
      reason,
    };
  }

  return {
    outcome: 'allow',
    obligations: makeObligationSet({ resultLabels: env.labels }),
    aggregateSensitivity: agg.aggregateSensitivity,
    reason: '',
  };
}

/**
 * Collapse a ContextDecision onto the declarative PolicyAction string.
 *
 * `constrain` maps to `allow` only when the host can carry obligations
 * (hasObligationChannel) or every obligation is already satisfied; otherwise
 * it fails closed to `deny`. `escalate` maps to `deny` (closest stop-and-review
 * action available in the TypeScript policy surface).
 */
export function toContextPolicyAction(
  decision: ContextDecision,
  hasObligationChannel: boolean,
): PolicyAction {
  if (decision.outcome === 'allow') return 'allow';
  if (decision.outcome === 'deny') return 'deny';
  if (decision.outcome === 'escalate') return 'deny';
  // constrain: allow only if the host can carry the obligations, or every
  // obligation is already satisfied. An empty obligation set on a channel-less
  // path does NOT grant allow (vacuous all_satisfied must not fail open).
  if (hasObligationChannel) return 'allow';
  if (decision.obligations.obligations.length > 0 && allSatisfied(decision.obligations)) return 'allow';
  return 'deny';
}

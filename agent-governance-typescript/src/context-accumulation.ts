// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { AggregationRuleSet } from './context-aggregation';
import { ContextEnvelope } from './context-envelope';
import { DataClassification, requireDataClassification } from './data-classification';
import { Obligation, ObligationSet } from './obligations';

/**
 * Post-execution accumulation and next-action gating.
 *
 * Ported from the Python reference (`agent_os/policies/context_accumulation.py`).
 *
 * Sensitivity accumulates from the labels an action actually produced, never from
 * a projection of an output that has not run yet. After folding, the next action is
 * gated against the accumulated envelope.
 */

/** Action token to the restriction that gates it. */
const RESTRICTED_ACTIONS: ReadonlyMap<string, string> = new Map([
  ['export', 'no_external_export'],
  ['delegate', 'no_external_delegation'],
  ['memory_write', 'no_memory_write'],
]);

/** Governance-level outcome of a context-aware decision. */
export enum ContextOutcome {
  Allow = 'allow',
  Constrain = 'constrain',
  Deny = 'deny',
  Escalate = 'escalate',
}

/** Fields accepted by the {@link ContextDecision} constructor. */
export interface ContextDecisionInit {
  outcome: ContextOutcome;
  obligations: ObligationSet;
  aggregateSensitivity: DataClassification;
  reason?: string;
}

/** A context-aware decision plus any obligations it carries. */
export class ContextDecision {
  readonly outcome: ContextOutcome;
  readonly obligations: ObligationSet;
  readonly aggregateSensitivity: DataClassification;
  readonly reason: string;

  constructor(init: ContextDecisionInit) {
    this.outcome = init.outcome;
    this.obligations = init.obligations;
    this.aggregateSensitivity = requireDataClassification(
      init.aggregateSensitivity,
      'aggregateSensitivity',
    );
    this.reason = init.reason ?? '';
  }
}

/**
 * Folds an action's actual result into `envelope` and re-runs aggregation.
 *
 * Runs after the action executed, so it folds real labels. The returned envelope
 * carries the updated sensitivity and the grow-only restrictions.
 */
export function accumulate(
  envelope: ContextEnvelope,
  resultLabels: Iterable<string>,
  resultSensitivity: DataClassification,
  ruleSet: AggregationRuleSet,
  categoryThreshold: number,
): ContextEnvelope {
  const folded = envelope.fold(resultLabels, resultSensitivity);
  const aggregation = ruleSet.evaluate(folded, categoryThreshold);
  const raised = folded.withAggregateSensitivity(aggregation.aggregateSensitivity);
  return raised.applyRestrictions(aggregation.restrictions);
}

/**
 * Gates `action` against the already-accumulated `envelope`.
 *
 * An explicit restriction token is a hard gate: it is enforced no matter what the
 * aggregate sensitivity is. The sensitivity floor is a second, independent trigger
 * for flow-bearing actions.
 */
export function decideNext(
  envelope: ContextEnvelope,
  action: string,
  ruleSet: AggregationRuleSet,
  categoryThreshold: number,
  restrictedFloor: DataClassification = DataClassification.Restricted,
): ContextDecision {
  const floor = requireDataClassification(restrictedFloor, 'restrictedFloor');
  const aggregation = ruleSet.evaluate(envelope, categoryThreshold);

  if (aggregation.escalate) {
    return new ContextDecision({
      outcome: ContextOutcome.Escalate,
      obligations: new ObligationSet({ resultLabels: envelope.labels }),
      aggregateSensitivity: aggregation.aggregateSensitivity,
      reason: 'aggregation threshold crossed with no governing rule',
    });
  }

  const gating = RESTRICTED_ACTIONS.get(action) ?? null;
  // Both the gate and the obligations read the restrictions the aggregation
  // *evaluated*, not the envelope's. evaluate seeds from envelope.restrictions, so
  // this is a superset: it can only gate more, never less. Reading the envelope
  // let a rule that adds a gating token without lifting sensitivity to the floor
  // slip through -- the token was in the aggregation result but not yet on the
  // envelope, so neither trigger fired.
  const effective = aggregation.restrictions;
  const restrictionPresent = gating !== null && effective.has(gating);
  const floorTriggered = gating !== null && aggregation.aggregateSensitivity >= floor;

  if (restrictionPresent || floorTriggered) {
    // A constrain carrying no obligations is a no-op for a host that enforces
    // through them. When the floor fires on an envelope with nothing recorded, the
    // gating token for the action is the constraint being applied, so name it.
    const keys = new Set<string>(effective);
    if (floorTriggered && gating !== null) {
      keys.add(gating);
    }
    const obligations = [...keys]
      .sort()
      .map((key) => new Obligation({ key }));
    const reason = restrictionPresent
      ? `action '${action}' restricted by '${gating}'`
      : `action '${action}' gated by sensitivity floor`;

    return new ContextDecision({
      outcome: ContextOutcome.Constrain,
      obligations: new ObligationSet({ obligations, resultLabels: envelope.labels }),
      aggregateSensitivity: aggregation.aggregateSensitivity,
      reason,
    });
  }

  return new ContextDecision({
    outcome: ContextOutcome.Allow,
    obligations: new ObligationSet({ resultLabels: envelope.labels }),
    aggregateSensitivity: aggregation.aggregateSensitivity,
  });
}

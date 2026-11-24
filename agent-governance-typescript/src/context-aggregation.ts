// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { requireIdentifier, snapshotTokens } from './context-tokens';
import { ContextEnvelope } from './context-envelope';
import {
  DataClassification,
  maximumClassification,
  requireDataClassification,
} from './data-classification';

/**
 * Aggregation evaluation for accumulated context governance.
 *
 * Ported from the Python reference (`agent_os/policies/context_aggregation.py`).
 *
 * Rules are authored per organization over *combinations* of accumulated labels.
 * A combination no rule covers escalates for review once it reaches the category
 * threshold, so an unknown combination cannot pass silently.
 */

/** Fields accepted by the {@link AggregationRule} constructor. */
export interface AggregationRuleInit {
  name: string;
  /** Every label here must be present for the rule to fire. Must not be empty. */
  allLabels: Iterable<string>;
  /** Sensitivity floor the rule imposes when it matches. */
  setsSensitivity: DataClassification;
  /** Restrictions the rule adds when it matches. */
  addsRestrictions?: Iterable<string>;
}

/**
 * One organization-authored rule over a label combination.
 *
 * An empty `allLabels` set matches every envelope and would silently defeat the
 * escalation backstop, so it is rejected.
 */
export class AggregationRule {
  readonly name: string;
  readonly allLabels: ReadonlySet<string>;
  readonly setsSensitivity: DataClassification;
  readonly addsRestrictions: ReadonlySet<string>;

  constructor(init: AggregationRuleInit) {
    this.name = requireIdentifier(init.name, 'name');
    this.allLabels = snapshotTokens(init.allLabels, 'allLabels');
    if (this.allLabels.size === 0) {
      throw new RangeError(
        `aggregation rule '${this.name}' must have a non-empty allLabels set`,
      );
    }
    this.setsSensitivity = requireDataClassification(init.setsSensitivity, 'setsSensitivity');
    this.addsRestrictions = snapshotTokens(init.addsRestrictions, 'addsRestrictions');
  }
}

/** Fields accepted by the {@link AggregationResult} constructor. */
export interface AggregationResultInit {
  aggregateSensitivity: DataClassification;
  restrictions: Iterable<string>;
  escalate: boolean;
  rulesApplied: Iterable<string>;
}

/** Outcome of evaluating an envelope against a rule set. */
export class AggregationResult {
  readonly aggregateSensitivity: DataClassification;
  readonly restrictions: ReadonlySet<string>;
  readonly escalate: boolean;
  readonly rulesApplied: readonly string[];

  constructor(init: AggregationResultInit) {
    this.aggregateSensitivity = requireDataClassification(
      init.aggregateSensitivity,
      'aggregateSensitivity',
    );
    this.restrictions = snapshotTokens(init.restrictions, 'restrictions');
    this.escalate = init.escalate;
    this.rulesApplied = [...init.rulesApplied];
  }
}

/** An ordered collection of aggregation rules. */
export class AggregationRuleSet {
  readonly rules: readonly AggregationRule[];

  constructor(rules: Iterable<AggregationRule> = []) {
    const snapshot = [...rules];
    // Shape is not enough. TypeScript's structural typing admits any object carrying the
    // right fields, and one with an empty `allLabels` matches every envelope -- which
    // suppresses the escalation backstop for combinations no rule actually covers. The
    // rule's own constructor validates its fields, so only its instances are safe here.
    if (snapshot.some((rule) => !(rule instanceof AggregationRule))) {
      throw new TypeError('rules must contain AggregationRule instances.');
    }
    this.rules = snapshot;
  }

  /**
   * Applies matching rules to `envelope` and applies the monotone backstop.
   *
   * The result sensitivity is the maximum of the envelope's current sensitivity
   * and every matching rule's floor, so an envelope that keeps growing without
   * crossing a declared combination keeps the classification it already earned.
   */
  evaluate(envelope: ContextEnvelope, categoryThreshold: number): AggregationResult {
    if (!Number.isInteger(categoryThreshold) || categoryThreshold < 1) {
      throw new RangeError(
        `categoryThreshold must be a positive integer, received ${String(categoryThreshold)}.`,
      );
    }

    let sensitivity = envelope.aggregateSensitivity;
    const restrictions = new Set<string>(envelope.restrictions);
    const applied: string[] = [];

    // `allLabels` is re-checked here, not only in the rule's constructor. A rule can reach this
    // point through `Object.create(AggregationRule.prototype)`, or have its own set emptied after
    // construction. An empty set makes `every` vacuously true, so the rule would match every
    // envelope and suppress the escalation backstop for combinations no rule actually covers.
    for (const rule of this.rules) {
      if (rule.allLabels.size === 0) {
        throw new TypeError(
          `aggregation rule '${String(rule.name)}' must have a non-empty allLabels set`,
        );
      }
    }

    for (const rule of this.rules) {
      const matches = [...rule.allLabels].every((label) => envelope.labels.has(label));
      if (!matches) {
        continue;
      }
      sensitivity = maximumClassification(sensitivity, rule.setsSensitivity);
      for (const restriction of rule.addsRestrictions) {
        restrictions.add(restriction);
      }
      applied.push(rule.name);
    }

    return new AggregationResult({
      aggregateSensitivity: sensitivity,
      restrictions,
      escalate: applied.length === 0 && envelope.labels.size >= categoryThreshold,
      rulesApplied: applied,
    });
  }
}

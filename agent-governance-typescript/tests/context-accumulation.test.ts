// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  AggregationRule,
  AggregationRuleSet,
} from '../src/context-aggregation';
import {
  ContextOutcome,
  accumulate,
  decideNext,
} from '../src/context-accumulation';
import { ContextEnvelope } from '../src/context-envelope';
import { DataClassification as DC } from '../src/data-classification';

const RULESET = new AggregationRuleSet([
  new AggregationRule({
    name: 'pii_financial_restricted',
    allLabels: ['pii', 'financial'],
    setsSensitivity: DC.Restricted,
    addsRestrictions: ['no_external_export'],
  }),
]);

// A rule that adds a gating token WITHOUT lifting sensitivity to the floor. That
// is the combination that used to slip through: the token is in the aggregation
// result but not yet on the envelope, and the floor never fires.
const LOW_SENSITIVITY_RESTRICTING_RULESET = new AggregationRuleSet([
  new AggregationRule({
    name: 'pii_location_no_export',
    allLabels: ['pii', 'location'],
    setsSensitivity: DC.Confidential,
    addsRestrictions: ['no_external_export'],
  }),
]);

function makeEnvelope(labels: string[] = [], sens: DC = DC.Internal, restrictions: string[] = []) {
  return new ContextEnvelope({
    envelopeId: 'e',
    workflowId: 'w',
    labels,
    aggregateSensitivity: sens,
    restrictions,
  });
}

const obligationKeys = (decision: { obligations: { obligations: readonly { key: string }[] } }) =>
  decision.obligations.obligations.map((obligation) => obligation.key).sort();

describe('accumulate()', () => {
  it('folds the labels the action actually produced', () => {
    const out = accumulate(makeEnvelope(['pii'], DC.Internal), ['financial'], DC.Confidential, RULESET, 99);

    expect(out.labels.has('financial')).toBe(true);
    expect(out.aggregateSensitivity).toBe(DC.Restricted);
    expect(out.restrictions.has('no_external_export')).toBe(true);
  });

  it('never lowers sensitivity', () => {
    const out = accumulate(makeEnvelope(['pii'], DC.Restricted), ['misc'], DC.Public, RULESET, 99);

    expect(out.aggregateSensitivity).toBe(DC.Restricted);
  });

  it('counts one version per fold and one per restriction application', () => {
    const before = makeEnvelope(['pii'], DC.Internal);
    const out = accumulate(before, ['financial'], DC.Confidential, RULESET, 99);

    expect(out.version).toBe(before.version + 2);
  });

  it('rejects a result sensitivity that is not a defined level', () => {
    expect(() =>
      accumulate(makeEnvelope(), ['pii'], undefined as never, RULESET, 99),
    ).toThrow(/newSensitivity/);
  });
});

describe('decideNext()', () => {
  it('gates the next action on the accumulated state', () => {
    const before = makeEnvelope(['pii'], DC.Internal);
    const accumulated = accumulate(before, ['financial'], DC.Confidential, RULESET, 99);
    const decision = decideNext(accumulated, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Constrain);
    expect(obligationKeys(decision)).toContain('no_external_export');
  });

  it('enforces an explicit restriction even below the sensitivity floor', () => {
    const e = makeEnvelope(['pii'], DC.Confidential, ['no_external_export']);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Constrain);
  });

  it('gates a flow-bearing action at the floor with no explicit restriction', () => {
    const e = makeEnvelope(['pii'], DC.Restricted);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Constrain);
  });

  it('names the restriction a rule just triggered, not the still-empty envelope set', () => {
    // No accumulate() ran, so the restriction was never folded onto the envelope.
    // decideNext re-evaluates aggregation, so the gate fires through the floor --
    // and the obligations must name the restriction the rule triggered. Otherwise
    // the caller is told to constrain the action without being told what to satisfy.
    const e = makeEnvelope(['pii', 'financial'], DC.Confidential);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Constrain);
    expect(obligationKeys(decision)).toEqual(['no_external_export']);
  });

  it('keeps the envelope restrictions and adds the new ones', () => {
    const e = makeEnvelope(['pii', 'financial'], DC.Confidential, ['no_print']);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(obligationKeys(decision)).toEqual(['no_external_export', 'no_print']);
  });

  it('gates on a restriction the aggregation derived, below the floor', () => {
    // Sensitivity stays at CONFIDENTIAL, under the RESTRICTED floor, so the floor
    // cannot be what gates this. The rule's restriction token has to.
    const e = makeEnvelope(['pii', 'location'], DC.Internal);
    const decision = decideNext(e, 'export', LOW_SENSITIVITY_RESTRICTING_RULESET, 99);

    expect(decision.aggregateSensitivity).toBe(DC.Confidential);
    expect(decision.outcome).toBe(ContextOutcome.Constrain);
    expect(obligationKeys(decision)).toEqual(['no_external_export']);
  });

  it('does not gate an unrelated action on a restriction meant for another one', () => {
    const e = makeEnvelope(['pii', 'location'], DC.Internal);
    const decision = decideNext(e, 'memory_write', LOW_SENSITIVITY_RESTRICTING_RULESET, 99);

    expect(decision.outcome).not.toBe(ContextOutcome.Constrain);
  });

  it('always names an obligation when the floor gates the action', () => {
    const e = makeEnvelope(['pii'], DC.Restricted);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Constrain);
    expect(obligationKeys(decision)).toEqual(['no_external_export']);
  });

  it('allows an action that carries no restriction and sits below the floor', () => {
    const e = makeEnvelope(['pii'], DC.Internal);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.outcome).toBe(ContextOutcome.Allow);
    expect(decision.aggregateSensitivity).toBe(DC.Internal);
  });

  it('escalates when the combination has no governing rule', () => {
    // No rule matches these labels, and there are at least as many as the
    // threshold, so the backstop escalates instead of letting them through.
    const e = makeEnvelope(['a', 'b', 'c'], DC.Internal);
    const decision = decideNext(e, 'read', RULESET, 3);

    expect(decision.outcome).toBe(ContextOutcome.Escalate);
    expect(decision.obligations.allSatisfied()).toBe(true);
  });

  it('rejects a restricted floor that is not a defined level', () => {
    const e = makeEnvelope(['pii'], DC.Internal);

    expect(() => decideNext(e, 'export', RULESET, 99, 12 as DC)).toThrow(RangeError);
  });
});

describe('ObligationSet', () => {
  it('is vacuously satisfied with no obligations', () => {
    const decision = decideNext(makeEnvelope(), 'read', RULESET, 99);

    expect(decision.obligations.allSatisfied()).toBe(true);
  });

  it('is not satisfied while an obligation is open', () => {
    const e = makeEnvelope(['pii'], DC.Restricted);
    const decision = decideNext(e, 'export', RULESET, 99);

    expect(decision.obligations.allSatisfied()).toBe(false);
  });
});

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  AggregationRule,
  AggregationRuleSet,
} from '../src/context-aggregation';
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

function makeEnvelope(
  labels: string[],
  sensitivity: DC = DC.Internal,
  restrictions: string[] = [],
) {
  return new ContextEnvelope({
    envelopeId: 'e',
    workflowId: 'w',
    labels,
    aggregateSensitivity: sensitivity,
    restrictions,
  });
}

describe('aggregation', () => {
  it('fires a rule on the label combination it was written for', () => {
    const result = RULESET.evaluate(makeEnvelope(['pii', 'financial']), 99);

    expect(result.aggregateSensitivity).toBe(DC.Restricted);
    expect(result.restrictions.has('no_external_export')).toBe(true);
    expect(result.rulesApplied).toEqual(['pii_financial_restricted']);
    expect(result.escalate).toBe(false);
  });

  it('keeps the classification when growth does not cross a declared combination', () => {
    const result = RULESET.evaluate(makeEnvelope(['pii', 'behavioral'], DC.Internal), 99);

    expect(result.aggregateSensitivity).toBe(DC.Internal);
    expect(result.rulesApplied).toEqual([]);
  });

  it('never lowers the envelope classification', () => {
    const result = RULESET.evaluate(makeEnvelope(['x'], DC.Confidential), 99);

    expect(result.aggregateSensitivity).toBeGreaterThanOrEqual(DC.Confidential);
  });

  it('escalates an uncovered combination at the category threshold', () => {
    const result = RULESET.evaluate(makeEnvelope(['a', 'b', 'c'], DC.Internal), 3);

    expect(result.escalate).toBe(true);
  });

  it('does not escalate below the threshold', () => {
    const result = RULESET.evaluate(makeEnvelope(['a', 'b'], DC.Internal), 3);

    expect(result.escalate).toBe(false);
  });

  it('does not escalate an empty envelope', () => {
    expect(RULESET.evaluate(makeEnvelope([]), 1).escalate).toBe(false);
  });

  it('rejects a category threshold below one', () => {
    expect(() => RULESET.evaluate(makeEnvelope(['a']), 0)).toThrow(/categoryThreshold/);
    expect(() => RULESET.evaluate(makeEnvelope(['a']), -1)).toThrow(/categoryThreshold/);
    expect(() => RULESET.evaluate(makeEnvelope(['a']), 1.5)).toThrow(/categoryThreshold/);
  });
});

describe('AggregationRule', () => {
  it('rejects an empty allLabels set, which would match every envelope', () => {
    expect(
      () =>
        new AggregationRule({
          name: 'empty_rule',
          allLabels: [],
          setsSensitivity: DC.TopSecret,
        }),
    ).toThrow(/non-empty/);
  });

  it('rejects a sensitivity floor that is not a defined level', () => {
    expect(
      () =>
        new AggregationRule({
          name: 'bad_floor',
          allLabels: ['pii'],
          setsSensitivity: 99 as DC,
        }),
    ).toThrow(RangeError);
  });

  it('rejects a rule name that is empty or padded', () => {
    expect(
      () => new AggregationRule({ name: '', allLabels: ['a'], setsSensitivity: DC.Public }),
    ).toThrow(TypeError);
    expect(
      () => new AggregationRule({ name: ' pii ', allLabels: ['a'], setsSensitivity: DC.Public }),
    ).toThrow(/whitespace/);
  });
});

describe('AggregationRuleSet shape check', () => {
  it('rejects an object that only looks like an AggregationRule', () => {
    // Structural typing admits this through the constructor's parameter type, and a rule
    // carrying an empty allLabels then matches every envelope, which suppresses the
    // escalation backstop for combinations no rule actually covers.
    const impostor = {
      name: 'not_a_rule',
      allLabels: [] as string[],
      setsSensitivity: DC.Restricted,
      addsRestrictions: [] as string[],
    };

    expect(() => new AggregationRuleSet([impostor as unknown as AggregationRule])).toThrow(
      TypeError,
    );
  });

  it('still accepts its own instances', () => {
    expect(() => new AggregationRuleSet([...RULESET.rules])).not.toThrow();
  });

  it('rejects a rule whose allLabels was emptied after construction', () => {
    const rule = new AggregationRule({
      name: 'emptied',
      allLabels: ['pii'],
      setsSensitivity: DC.Restricted,
      addsRestrictions: [],
    });
    (rule.allLabels as Set<string>).clear();

    const ruleset = new AggregationRuleSet([rule]);
    expect(() => ruleset.evaluate(makeEnvelope(['pii', 'financial', 'phi']), 3)).toThrow(TypeError);
  });

  it('rejects a rule that skipped its constructor', () => {
    // `instanceof` is satisfied by Object.create(AggregationRule.prototype), so the check in the
    // constructor cannot be the only one: an empty allLabels matches every envelope.
    const fake = Object.create(AggregationRule.prototype) as AggregationRule;
    Object.assign(fake, {
      name: 'skipped_constructor',
      allLabels: new Set<string>(),
      setsSensitivity: DC.Restricted,
      addsRestrictions: new Set<string>(),
    });

    const ruleset = new AggregationRuleSet([fake]);
    expect(() => ruleset.evaluate(makeEnvelope(['pii', 'financial', 'phi']), 3)).toThrow(TypeError);
  });
});

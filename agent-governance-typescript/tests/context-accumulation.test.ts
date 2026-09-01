// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { DataClassification } from '../src/data-classification';
import {
  accumulate,
  decideNext,
  toContextPolicyAction,
} from '../src/context-accumulation';
import {
  makeAggregationRule,
  evaluateAggregation,
} from '../src/context-aggregation';
import type { AggregationRuleSet } from '../src/context-aggregation';
import {
  makeContextEnvelope,
  fold,
  applyRestrictions,
  envelopeReference,
} from '../src/context-envelope';
import { mergeRestrictions } from '../src/context-delegation';
import {
  contextEvent,
  CONTEXT_ENVELOPE_CREATED,
  CONTEXT_ENVELOPE_UPDATED,
} from '../src/context-audit';
import {
  makeObligationSet,
  allSatisfied,
} from '../src/obligations';
import {
  detectPii,
  detectPhi,
  detectPci,
  classifyText,
  DataAccessEvaluator,
  makeABACPolicy,
  makeDataLabel,
} from '../src/data-classification';

const DC = DataClassification;

const RULESET: AggregationRuleSet = {
  rules: [
    makeAggregationRule({
      name: 'pii_financial_restricted',
      allLabels: new Set(['pii', 'financial']),
      setsSensitivity: DC.RESTRICTED,
      addsRestrictions: new Set(['no_external_export']),
    }),
  ],
};

function makeEnv(opts: { labels?: string[]; sensitivity?: DataClassification; restrictions?: string[] } = {}) {
  return makeContextEnvelope({
    envelopeId: 'e',
    workflowId: 'w',
    labels: new Set(opts.labels ?? []),
    aggregateSensitivity: opts.sensitivity ?? DC.INTERNAL,
    restrictions: new Set(opts.restrictions ?? []),
  });
}

// ---------------------------------------------------------------------------
// ContextEnvelope — fold and applyRestrictions
// ---------------------------------------------------------------------------

describe('ContextEnvelope', () => {
  it('fold joins labels and raises sensitivity', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.INTERNAL });
    const out = fold(e, ['financial'], DC.CONFIDENTIAL);
    expect(out.labels.has('pii')).toBe(true);
    expect(out.labels.has('financial')).toBe(true);
    expect(out.aggregateSensitivity).toBe(DC.CONFIDENTIAL);
    expect(out.version).toBe(e.version + 1);
    // original is unchanged
    expect(e.labels.has('financial')).toBe(false);
  });

  it('fold is idempotent on already-present labels', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.CONFIDENTIAL });
    const out = fold(e, ['pii'], DC.INTERNAL);
    expect(out.labels.size).toBe(e.labels.size);
    expect(out.aggregateSensitivity).toBe(e.aggregateSensitivity);
  });

  it('fold is commutative', () => {
    const e = makeEnv();
    const a = fold(fold(e, ['pii'], DC.INTERNAL), ['financial'], DC.CONFIDENTIAL);
    const b = fold(fold(e, ['financial'], DC.CONFIDENTIAL), ['pii'], DC.INTERNAL);
    expect([...a.labels].sort()).toEqual([...b.labels].sort());
    expect(a.aggregateSensitivity).toBe(b.aggregateSensitivity);
  });

  it('sensitivity is a max-lattice (never lowers)', () => {
    const e = makeEnv();
    const out = fold(fold(e, ['a'], DC.RESTRICTED), ['b'], DC.PUBLIC);
    expect(out.aggregateSensitivity).toBe(DC.RESTRICTED);
  });

  it('restrictions are grow-only', () => {
    const e = makeEnv({ restrictions: ['no_external_export'] });
    const out = applyRestrictions(e, []);
    expect(out.restrictions.has('no_external_export')).toBe(true);
    const out2 = applyRestrictions(out, ['no_memory_write']);
    expect(out2.restrictions.has('no_external_export')).toBe(true);
    expect(out2.restrictions.has('no_memory_write')).toBe(true);
  });

  it('envelopeReference exposes only id and sensitivity', () => {
    const e = makeContextEnvelope({
      envelopeId: 'env-abc',
      workflowId: 'wf-corr-1',
      labels: new Set(['pii', 'financial']),
      aggregateSensitivity: DC.RESTRICTED,
      restrictions: new Set(['no_external_export']),
      version: 7,
      parentEnvelopeId: 'parent-xyz',
      createdAt: '2026-06-04T00:00:00Z',
    });
    const ref = envelopeReference(e);
    expect(ref.envelopeId).toBe('env-abc');
    expect(ref.sensitivity).toBe(DC.RESTRICTED);
    expect(Object.keys(ref)).toEqual(['envelopeId', 'sensitivity']);
  });
});

// ---------------------------------------------------------------------------
// AggregationRuleSet — evaluateAggregation
// ---------------------------------------------------------------------------

describe('evaluateAggregation', () => {
  it('applies a matching rule', () => {
    const e = makeEnv({ labels: ['pii', 'financial'], sensitivity: DC.CONFIDENTIAL });
    const result = evaluateAggregation(e, RULESET, 99);
    expect(result.rulesApplied).toContain('pii_financial_restricted');
    expect(result.aggregateSensitivity).toBe(DC.RESTRICTED);
    expect(result.restrictions.has('no_external_export')).toBe(true);
    expect(result.escalate).toBe(false);
  });

  it('escalates when threshold reached with no matching rule', () => {
    const e = makeEnv({ labels: ['a', 'b', 'c'], sensitivity: DC.INTERNAL });
    const result = evaluateAggregation(e, RULESET, 3);
    expect(result.escalate).toBe(true);
  });

  it('does not escalate below threshold', () => {
    const e = makeEnv({ labels: ['a', 'b'], sensitivity: DC.INTERNAL });
    const result = evaluateAggregation(e, RULESET, 5);
    expect(result.escalate).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// accumulate
// ---------------------------------------------------------------------------

describe('accumulate', () => {
  it('folds result labels and fires aggregation rule', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.INTERNAL });
    const out = accumulate(e, ['financial'], DC.CONFIDENTIAL, RULESET, 99);
    expect(out.labels.has('financial')).toBe(true);
    expect(out.aggregateSensitivity).toBe(DC.RESTRICTED);
    expect(out.restrictions.has('no_external_export')).toBe(true);
  });

  it('never lowers sensitivity', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.RESTRICTED });
    const out = accumulate(e, ['misc'], DC.PUBLIC, RULESET, 99);
    expect(out.aggregateSensitivity).toBe(DC.RESTRICTED);
  });
});

// ---------------------------------------------------------------------------
// decideNext
// ---------------------------------------------------------------------------

describe('decideNext', () => {
  it('gates action when restriction is present', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.INTERNAL });
    const acc = accumulate(e, ['financial'], DC.CONFIDENTIAL, RULESET, 99);
    const decision = decideNext(acc, 'export', RULESET, 99);
    expect(decision.outcome).toBe('constrain');
    const keys = decision.obligations.obligations.map((o) => o.key);
    expect(keys).toContain('no_external_export');
  });

  it('accumulation never lowers sensitivity', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.RESTRICTED });
    const out = accumulate(e, ['misc'], DC.PUBLIC, RULESET, 99);
    expect(out.aggregateSensitivity).toBe(DC.RESTRICTED);
  });

  it('explicit restriction gates below floor', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.CONFIDENTIAL, restrictions: ['no_external_export'] });
    const decision = decideNext(e, 'export', RULESET, 99);
    expect(decision.outcome).toBe('constrain');
  });

  it('floor triggers flow-bearing action without explicit restriction', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.RESTRICTED });
    const decision = decideNext(e, 'export', RULESET, 99);
    expect(decision.outcome).toBe('constrain');
  });

  it('allows unrestricted action', () => {
    const e = makeEnv({ labels: ['pii'], sensitivity: DC.INTERNAL });
    const decision = decideNext(e, 'read', RULESET, 99);
    expect(decision.outcome).toBe('allow');
  });

  it('escalates on threshold with no matching rule', () => {
    const e = makeEnv({ labels: ['a', 'b', 'c'], sensitivity: DC.INTERNAL });
    const decision = decideNext(e, 'read', RULESET, 3);
    expect(decision.outcome).toBe('escalate');
  });
});

// ---------------------------------------------------------------------------
// toContextPolicyAction
// ---------------------------------------------------------------------------

describe('toContextPolicyAction', () => {
  it('allow outcome -> allow', () => {
    const d = { outcome: 'allow' as const, obligations: makeObligationSet(), aggregateSensitivity: DC.PUBLIC, reason: '' };
    expect(toContextPolicyAction(d, false)).toBe('allow');
  });

  it('deny outcome -> deny', () => {
    const d = { outcome: 'deny' as const, obligations: makeObligationSet(), aggregateSensitivity: DC.PUBLIC, reason: '' };
    expect(toContextPolicyAction(d, false)).toBe('deny');
  });

  it('escalate outcome -> deny', () => {
    const d = { outcome: 'escalate' as const, obligations: makeObligationSet(), aggregateSensitivity: DC.RESTRICTED, reason: '' };
    expect(toContextPolicyAction(d, false)).toBe('deny');
  });

  it('constrain + obligation channel -> allow', () => {
    const d = {
      outcome: 'constrain' as const,
      obligations: { obligations: [{ key: 'no_external_export', satisfied: false }], resultLabels: new Set<string>() },
      aggregateSensitivity: DC.RESTRICTED,
      reason: '',
    };
    expect(toContextPolicyAction(d, true)).toBe('allow');
  });

  it('constrain + no channel + unsatisfied -> deny', () => {
    const d = {
      outcome: 'constrain' as const,
      obligations: { obligations: [{ key: 'no_external_export', satisfied: false }], resultLabels: new Set<string>() },
      aggregateSensitivity: DC.RESTRICTED,
      reason: '',
    };
    expect(toContextPolicyAction(d, false)).toBe('deny');
  });

  it('constrain + no channel + all satisfied -> allow', () => {
    const d = {
      outcome: 'constrain' as const,
      obligations: { obligations: [{ key: 'no_external_export', satisfied: true }], resultLabels: new Set<string>() },
      aggregateSensitivity: DC.RESTRICTED,
      reason: '',
    };
    expect(toContextPolicyAction(d, false)).toBe('allow');
  });

  it('constrain + empty obligations + no channel -> deny (vacuous must not fail open)', () => {
    const d = {
      outcome: 'constrain' as const,
      obligations: makeObligationSet(),
      aggregateSensitivity: DC.RESTRICTED,
      reason: '',
    };
    expect(toContextPolicyAction(d, false)).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// mergeRestrictions (delegation)
// ---------------------------------------------------------------------------

describe('mergeRestrictions', () => {
  it('child inherits parent restrictions', () => {
    const parent = makeEnv({ restrictions: ['no_external_export'] });
    const merged = mergeRestrictions(parent, ['no_memory_write']);
    expect(merged.has('no_external_export')).toBe(true);
    expect(merged.has('no_memory_write')).toBe(true);
  });

  it('child cannot drop parent restriction', () => {
    const parent = makeEnv({ restrictions: ['no_external_export'] });
    const merged = mergeRestrictions(parent, []);
    expect(merged.has('no_external_export')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// contextEvent (audit)
// ---------------------------------------------------------------------------

describe('contextEvent', () => {
  it('records label and restriction additions', () => {
    const before = makeEnv({ labels: ['pii'], sensitivity: DC.INTERNAL });
    const after = fold(applyRestrictions(
      fold(before, ['financial'], DC.CONFIDENTIAL),
      ['no_external_export'],
    ), [], DC.INTERNAL);
    const evt = contextEvent(CONTEXT_ENVELOPE_UPDATED, 'agent-1', before, after, ['pii_financial_restricted']);
    expect(evt.labelsAdded.has('financial')).toBe(true);
    expect(evt.restrictionsAdded.has('no_external_export')).toBe(true);
    expect(evt.previousSensitivity).toBe(DC.INTERNAL);
    expect(evt.newSensitivity).toBe(DC.CONFIDENTIAL);
    expect(evt.classification).toBe(DC.CONFIDENTIAL);
    expect(evt.rulesApplied).toContain('pii_financial_restricted');
  });

  it('classification is max of before and after sensitivity', () => {
    const before = makeEnv({ sensitivity: DC.RESTRICTED });
    const after = makeEnv({ sensitivity: DC.INTERNAL });
    const evt = contextEvent(CONTEXT_ENVELOPE_CREATED, 'agent-1', before, after);
    expect(evt.classification).toBe(DC.RESTRICTED);
  });
});

// ---------------------------------------------------------------------------
// ObligationSet
// ---------------------------------------------------------------------------

describe('ObligationSet', () => {
  it('allSatisfied is true when all obligations satisfied', () => {
    const os = makeObligationSet({
      obligations: [{ key: 'a', satisfied: true }, { key: 'b', satisfied: true }],
    });
    expect(allSatisfied(os)).toBe(true);
  });

  it('allSatisfied is false when any obligation unsatisfied', () => {
    const os = makeObligationSet({
      obligations: [{ key: 'a', satisfied: true }, { key: 'b', satisfied: false }],
    });
    expect(allSatisfied(os)).toBe(false);
  });

  it('allSatisfied is true for empty set', () => {
    expect(allSatisfied(makeObligationSet())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Data Classification helpers
// ---------------------------------------------------------------------------

describe('PII/PHI/PCI detection', () => {
  it('detects SSN', () => {
    expect(detectPii('SSN: 123-45-6789')).toContain('SSN');
  });

  it('detects email', () => {
    expect(detectPii('Contact: user@example.com')).toContain('email');
  });

  it('detects phone number', () => {
    expect(detectPii('Call: 555-123-4567')).toContain('phone');
  });

  it('detects MRN', () => {
    expect(detectPhi('MRN: 1234567')).toContain('MRN');
  });

  it('detects credit card', () => {
    expect(detectPci('Card: 4111111111111111')).toContain('credit-card');
  });

  it('classifyText combines categories', () => {
    const label = classifyText('user@example.com and MRN: 1234567');
    expect(label.categories).toContain('PII');
    expect(label.categories).toContain('PHI');
    expect(label.classification).toBe(DC.RESTRICTED);
  });

  it('classifyText returns PUBLIC for benign text', () => {
    const label = classifyText('Hello world');
    expect(label.classification).toBe(DC.PUBLIC);
    expect(label.categories).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DataAccessEvaluator (ABAC)
// ---------------------------------------------------------------------------

describe('DataAccessEvaluator', () => {
  it('denies when no policy for agent', () => {
    const evaluator = new DataAccessEvaluator([]);
    const decision = evaluator.evaluate('agent-x', makeDataLabel({ classification: DC.PUBLIC }));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/No ABAC policy/);
  });

  it('allows when classification within limit', () => {
    const policy = makeABACPolicy({ agentId: 'agent-1', maxClassification: DC.CONFIDENTIAL });
    const evaluator = new DataAccessEvaluator([policy]);
    const decision = evaluator.evaluate('agent-1', makeDataLabel({ classification: DC.INTERNAL }));
    expect(decision.allowed).toBe(true);
  });

  it('denies when classification exceeds max', () => {
    const policy = makeABACPolicy({ agentId: 'agent-1', maxClassification: DC.INTERNAL });
    const evaluator = new DataAccessEvaluator([policy]);
    const decision = evaluator.evaluate('agent-1', makeDataLabel({ classification: DC.CONFIDENTIAL }));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/exceeds max/);
  });

  it('denies on denied category', () => {
    const policy = makeABACPolicy({ agentId: 'agent-1', maxClassification: DC.TOP_SECRET, deniedCategories: ['PII'] });
    const evaluator = new DataAccessEvaluator([policy]);
    const decision = evaluator.evaluate('agent-1', makeDataLabel({ classification: DC.INTERNAL, categories: ['PII'] }));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/explicitly denied/);
  });

  it('denies on geography mismatch', () => {
    const policy = makeABACPolicy({ agentId: 'agent-1', maxClassification: DC.TOP_SECRET, requiredGeography: 'US' });
    const evaluator = new DataAccessEvaluator([policy]);
    const decision = evaluator.evaluate('agent-1', makeDataLabel({ classification: DC.INTERNAL, geography: 'EU' }));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/Geography/);
  });

  it('denies when requiredGeography is set but geography label is absent (fail-closed)', () => {
    // Unlabeled data must not bypass the geography restriction — the check must
    // deny rather than skip when dataLabel.geography is empty.
    const policy = makeABACPolicy({ agentId: 'agent-1', maxClassification: DC.TOP_SECRET, requiredGeography: 'US' });
    const evaluator = new DataAccessEvaluator([policy]);
    const decision = evaluator.evaluate('agent-1', makeDataLabel({ classification: DC.INTERNAL, geography: '' }));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/absent|Geography/i);
  });
});

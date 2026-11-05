// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { ContextEnvelope, EnvelopeReference } from '../src/context-envelope';
import { DataClassification as DC } from '../src/data-classification';

function makeEnvelope(init: Partial<ConstructorParameters<typeof ContextEnvelope>[0]> = {}) {
  return new ContextEnvelope({ envelopeId: 'env1', workflowId: 'wf1', ...init });
}

describe('ContextEnvelope', () => {
  it('folds new labels and raises sensitivity without touching the source', () => {
    const e = makeEnvelope({ labels: ['pii'], aggregateSensitivity: DC.Internal });
    const out = e.fold(['financial'], DC.Confidential);

    expect([...out.labels].sort()).toEqual(['financial', 'pii']);
    expect(out.aggregateSensitivity).toBe(DC.Confidential);
    expect(out.version).toBe(e.version + 1);

    expect([...e.labels]).toEqual(['pii']);
    expect(e.aggregateSensitivity).toBe(DC.Internal);
    expect(e.version).toBe(0);
  });

  it('is idempotent: folding a label and a level it already holds changes nothing', () => {
    const e = makeEnvelope({ labels: ['pii'], aggregateSensitivity: DC.Confidential });
    const out = e.fold(['pii'], DC.Internal);

    expect([...out.labels]).toEqual(['pii']);
    expect(out.aggregateSensitivity).toBe(DC.Confidential);
  });

  it('is commutative: the fold order does not change the state', () => {
    const e = makeEnvelope();
    const a = e.fold(['pii'], DC.Internal).fold(['financial'], DC.Confidential);
    const b = e.fold(['financial'], DC.Confidential).fold(['pii'], DC.Internal);

    expect([...a.labels].sort()).toEqual([...b.labels].sort());
    expect(a.aggregateSensitivity).toBe(b.aggregateSensitivity);
  });

  it('keeps sensitivity on a max lattice: a low fold never lowers it', () => {
    const e = makeEnvelope();
    const out = e.fold(['a'], DC.Restricted).fold(['b'], DC.Public);

    expect(out.aggregateSensitivity).toBe(DC.Restricted);
  });

  it('keeps restrictions grow-only', () => {
    const e = makeEnvelope({ restrictions: ['no_external_export'] });
    const out = e.applyRestrictions([]);

    expect([...out.restrictions]).toEqual(['no_external_export']);
    expect(out.version).toBe(e.version + 1);

    const out2 = out.applyRestrictions(['no_memory_write']);
    expect([...out2.restrictions].sort()).toEqual(['no_external_export', 'no_memory_write']);
  });

  it('rejects a sensitivity that is not a defined level', () => {
    expect(() => makeEnvelope({ aggregateSensitivity: 9 as DC })).toThrow(RangeError);
    expect(() => makeEnvelope({ aggregateSensitivity: -1 as DC })).toThrow(RangeError);
    expect(() => makeEnvelope({ aggregateSensitivity: NaN })).toThrow(RangeError);
  });

  it('treats an omitted sensitivity as Public, like the reference default', () => {
    expect(makeEnvelope().aggregateSensitivity).toBe(DC.Public);
  });

  it('rejects an undefined or NaN sensitivity coming from a fold', () => {
    const e = makeEnvelope({ aggregateSensitivity: DC.Restricted });

    expect(() => e.fold(['pii'], NaN as DC)).toThrow(/newSensitivity/);
    expect(() => e.fold(['pii'], undefined as never)).toThrow(/newSensitivity/);
    expect(() => e.fold(['pii'], 42 as DC)).toThrow(/newSensitivity/);
  });

  it('rejects a negative or non-integer version', () => {
    expect(() => makeEnvelope({ version: -1 })).toThrow(RangeError);
    expect(() => makeEnvelope({ version: 1.5 })).toThrow(RangeError);
  });

  it('requires non-empty identifiers for the envelope and the workflow', () => {
    expect(() => new ContextEnvelope({ envelopeId: '', workflowId: 'wf1' })).toThrow(TypeError);
    expect(() => new ContextEnvelope({ envelopeId: ' env1 ', workflowId: 'wf1' })).toThrow(
      /whitespace/,
    );
  });

  describe('reference()', () => {
    const loaded = () =>
      makeEnvelope({
        envelopeId: 'env-abc',
        workflowId: 'wf-corr-1',
        labels: ['pii', 'financial'],
        aggregateSensitivity: DC.Restricted,
        restrictions: ['no_external_export'],
        version: 7,
        parentEnvelopeId: 'parent-xyz',
        createdAt: '2026-06-04T00:00:00Z',
      });

    it('exposes the envelope id and the sensitivity only', () => {
      const ref = loaded().reference();

      expect(ref).toBeInstanceOf(EnvelopeReference);
      expect(Object.keys(ref).sort()).toEqual(['envelopeId', 'sensitivity']);
      expect((ref as unknown as Record<string, unknown>).labels).toBeUndefined();
      expect((ref as unknown as Record<string, unknown>).restrictions).toBeUndefined();
      expect((ref as unknown as Record<string, unknown>).version).toBeUndefined();
      expect((ref as unknown as Record<string, unknown>).workflowId).toBeUndefined();
      expect((ref as unknown as Record<string, unknown>).createdAt).toBeUndefined();
    });

    it('carries the aggregate sensitivity and the lineage id', () => {
      const env = loaded();
      const ref = env.reference();

      expect(ref.sensitivity).toBe(env.aggregateSensitivity);
      expect(ref.sensitivity).toBe(DC.Restricted);
      expect(ref.envelopeId).toBe(env.envelopeId);
    });
  });
});

describe('ContextEnvelope token set ownership', () => {
  it('gives each envelope its own empty set', () => {
    // ReadonlySet is a compile-time type only, so one empty set shared by every envelope
    // would let a caller mutating what it was handed surface in all the others.
    const a = makeEnvelope();
    const b = makeEnvelope();

    expect(a.labels).not.toBe(b.labels);
    (a.labels as Set<string>).add('pii');
    expect([...b.labels]).toEqual([]);
  });

  it('reuses an unchanged set on a derived envelope instead of copying it', () => {
    // Re-snapshotting a field that did not change on every derived value made accumulate
    // quadratic: three copies per step.
    const e = makeEnvelope({ labels: ['pii'], restrictions: ['no_memory_write'] });
    const derived = e.withAggregateSensitivity(DC.Restricted);

    expect(derived.labels).toBe(e.labels);
    expect(derived.restrictions).toBe(e.restrictions);
  });
});

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { ContextEnvelope } from '../src/context-envelope';
import { mergeRestrictions } from '../src/context-delegation';

function parent(restrictions: string[] = []) {
  return new ContextEnvelope({ envelopeId: 'p', workflowId: 'w', restrictions });
}

describe('mergeRestrictions()', () => {
  it('gives the child the parent restrictions', () => {
    expect([...mergeRestrictions(parent(['no_external_export']), [])]).toEqual([
      'no_external_export',
    ]);
  });

  it('does not let the child drop a parent restriction', () => {
    expect(mergeRestrictions(parent(['no_external_export']), []).has('no_external_export')).toBe(
      true,
    );
  });

  it('lets the child add restrictions', () => {
    expect(
      [...mergeRestrictions(parent(['no_external_export']), ['no_memory_write'])].sort(),
    ).toEqual(['no_external_export', 'no_memory_write']);
  });

  it('accumulates the union along a delegation chain', () => {
    const hop1 = mergeRestrictions(parent(['a']), ['b']);
    const child = new ContextEnvelope({
      envelopeId: 'c',
      workflowId: 'w',
      restrictions: hop1,
    });
    const hop2 = mergeRestrictions(child, ['c']);

    expect([...hop2].sort()).toEqual(['a', 'b', 'c']);
  });
});

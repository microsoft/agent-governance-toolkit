// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  CONTEXT_AGGREGATION_ELEVATED,
  CONTEXT_ENVELOPE_UPDATED,
  contextEvent,
} from '../src/context-audit';
import { ContextEnvelope } from '../src/context-envelope';
import { DataClassification as DC } from '../src/data-classification';

function env(init: Partial<ConstructorParameters<typeof ContextEnvelope>[0]>) {
  return new ContextEnvelope({ envelopeId: 'e', workflowId: 'w', ...init });
}

describe('contextEvent()', () => {
  it('records what the aggregation elevated', () => {
    const before = env({ labels: ['pii'], aggregateSensitivity: DC.Confidential });
    const after = env({
      labels: ['pii', 'financial'],
      aggregateSensitivity: DC.Restricted,
      restrictions: ['no_external_export'],
    });

    const event = contextEvent(CONTEXT_AGGREGATION_ELEVATED, 'agent.customer-success', before, after, [
      'pii_financial_restricted',
    ]);

    expect(event.previousSensitivity).toBe(DC.Confidential);
    expect(event.newSensitivity).toBe(DC.Restricted);
    expect([...event.labelsAdded]).toEqual(['financial']);
    expect([...event.restrictionsAdded]).toEqual(['no_external_export']);
    expect(event.rulesApplied).toEqual(['pii_financial_restricted']);
  });

  it('carries a classification floor of the most sensitive envelope', () => {
    const before = env({ aggregateSensitivity: DC.Confidential });
    const after = env({ aggregateSensitivity: DC.Restricted });

    const event = contextEvent(CONTEXT_ENVELOPE_UPDATED, 'a', before, after);

    expect(event.classification).toBeGreaterThanOrEqual(after.aggregateSensitivity);
  });

  it('reports no additions when nothing changed', () => {
    const same = env({ labels: ['pii'], aggregateSensitivity: DC.Internal });
    const event = contextEvent(CONTEXT_ENVELOPE_UPDATED, 'a', same, same);

    expect([...event.labelsAdded]).toEqual([]);
    expect([...event.restrictionsAdded]).toEqual([]);
    expect(event.rulesApplied).toEqual([]);
  });
});

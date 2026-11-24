// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { ContextEnvelope } from './context-envelope';
import { differenceTokens, snapshotTokens } from './context-tokens';
import { DataClassification, maximumClassification } from './data-classification';

/**
 * Audit events for context envelope transitions.
 *
 * Ported from the Python reference (`agent_os/policies/context_audit.py`).
 *
 * A transition event names which labels and restrictions accumulated, so the event
 * is itself sensitive: every event carries a classification floor of at least the
 * envelope's aggregate sensitivity.
 */

export const CONTEXT_ENVELOPE_CREATED = 'CONTEXT_ENVELOPE_CREATED';
export const CONTEXT_ENVELOPE_UPDATED = 'CONTEXT_ENVELOPE_UPDATED';
export const CONTEXT_AGGREGATION_ELEVATED = 'CONTEXT_AGGREGATION_ELEVATED';
export const CONTEXT_DELEGATED = 'CONTEXT_DELEGATED';
export const CONTEXT_REDACTED = 'CONTEXT_REDACTED';
export const DERIVED_ARTIFACT_LABELED = 'DERIVED_ARTIFACT_LABELED';

/** Fields accepted by the {@link ContextEvent} constructor. */
export interface ContextEventInit {
  eventType: string;
  agentId: string;
  contextEnvelopeId: string;
  previousSensitivity: DataClassification;
  newSensitivity: DataClassification;
  labelsAdded: Iterable<string>;
  rulesApplied: Iterable<string>;
  restrictionsAdded: Iterable<string>;
  classification: DataClassification;
}

/** A recorded transition between two envelope versions. */
export class ContextEvent {
  readonly eventType: string;
  readonly agentId: string;
  readonly contextEnvelopeId: string;
  readonly previousSensitivity: DataClassification;
  readonly newSensitivity: DataClassification;
  readonly labelsAdded: ReadonlySet<string>;
  readonly rulesApplied: readonly string[];
  readonly restrictionsAdded: ReadonlySet<string>;
  readonly classification: DataClassification;

  constructor(init: ContextEventInit) {
    this.eventType = init.eventType;
    this.agentId = init.agentId;
    this.contextEnvelopeId = init.contextEnvelopeId;
    this.previousSensitivity = init.previousSensitivity;
    this.newSensitivity = init.newSensitivity;
    this.labelsAdded = snapshotTokens(init.labelsAdded, 'labelsAdded');
    this.rulesApplied = [...init.rulesApplied];
    this.restrictionsAdded = snapshotTokens(init.restrictionsAdded, 'restrictionsAdded');
    this.classification = init.classification;
  }
}

/**
 * Builds the event describing the transition `before` to `after`.
 *
 * The event's own classification is the max of the two envelopes', so it is never
 * less protected than the state it describes.
 */
export function contextEvent(
  eventType: string,
  agentId: string,
  before: ContextEnvelope,
  after: ContextEnvelope,
  rulesApplied: readonly string[] = [],
): ContextEvent {
  return new ContextEvent({
    eventType,
    agentId,
    contextEnvelopeId: after.envelopeId,
    previousSensitivity: before.aggregateSensitivity,
    newSensitivity: after.aggregateSensitivity,
    labelsAdded: differenceTokens(after.labels, before.labels),
    rulesApplied,
    restrictionsAdded: differenceTokens(after.restrictions, before.restrictions),
    classification: maximumClassification(
      before.aggregateSensitivity,
      after.aggregateSensitivity,
    ),
  });
}

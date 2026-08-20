// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit events for context envelope transitions.
 *
 * Emits CONTEXT_* events describing how an envelope changed across an action
 * or delegation. Every event carries its own classification floor — at least
 * the envelope's aggregate sensitivity.
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/context_audit.py.
 * Refs #3084.
 */

import { DataClassification } from './data-classification';
import type { ContextEnvelope } from './context-envelope';

export const CONTEXT_ENVELOPE_CREATED = 'CONTEXT_ENVELOPE_CREATED';
export const CONTEXT_ENVELOPE_UPDATED = 'CONTEXT_ENVELOPE_UPDATED';
export const CONTEXT_AGGREGATION_ELEVATED = 'CONTEXT_AGGREGATION_ELEVATED';
export const CONTEXT_DELEGATED = 'CONTEXT_DELEGATED';
export const CONTEXT_REDACTED = 'CONTEXT_REDACTED';
export const DERIVED_ARTIFACT_LABELED = 'DERIVED_ARTIFACT_LABELED';

/** A recorded transition between two envelope versions. */
export interface ContextEvent {
  readonly eventType: string;
  readonly agentId: string;
  readonly contextEnvelopeId: string;
  readonly previousSensitivity: DataClassification;
  readonly newSensitivity: DataClassification;
  readonly labelsAdded: ReadonlySet<string>;
  readonly rulesApplied: readonly string[];
  readonly restrictionsAdded: ReadonlySet<string>;
  readonly classification: DataClassification;
}

/** Build a ContextEvent describing the transition before -> after. */
export function contextEvent(
  eventType: string,
  agentId: string,
  before: ContextEnvelope,
  after: ContextEnvelope,
  rulesApplied: readonly string[] = [],
): ContextEvent {
  const classification = Math.max(
    before.aggregateSensitivity,
    after.aggregateSensitivity,
  ) as DataClassification;

  const labelsAdded = new Set([...after.labels].filter((l) => !before.labels.has(l)));
  const restrictionsAdded = new Set(
    [...after.restrictions].filter((r) => !before.restrictions.has(r)),
  );

  return {
    eventType,
    agentId,
    contextEnvelopeId: after.envelopeId,
    previousSensitivity: before.aggregateSensitivity,
    newSensitivity: after.aggregateSensitivity,
    labelsAdded,
    rulesApplied,
    restrictionsAdded,
    classification,
  };
}

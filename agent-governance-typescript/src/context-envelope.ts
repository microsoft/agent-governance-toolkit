// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Context envelope: accumulated governance state for a workflow.
 *
 * A ContextEnvelope is an immutable, versioned value object that records the
 * labels and sensitivity accumulated so far in a workflow. Sensitivity is a
 * max-lattice over DataClassification (it only ever rises); restrictions are a
 * grow-only set (they can be added but never dropped).
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/context_envelope.py.
 * Refs #3084.
 */

import { DataClassification } from './data-classification';

/** Immutable, versioned accumulation of workflow governance state. */
export interface ContextEnvelope {
  readonly envelopeId: string;
  readonly workflowId: string;
  readonly labels: ReadonlySet<string>;
  readonly aggregateSensitivity: DataClassification;
  readonly restrictions: ReadonlySet<string>;
  readonly version: number;
  readonly parentEnvelopeId: string | null;
  readonly createdAt: string;
}

export function makeContextEnvelope(
  opts: Pick<ContextEnvelope, 'envelopeId' | 'workflowId'> & {
    labels?: Iterable<string>;
    aggregateSensitivity?: DataClassification;
    restrictions?: Iterable<string>;
    version?: number;
    parentEnvelopeId?: string | null;
    createdAt?: string;
  },
): ContextEnvelope {
  return {
    envelopeId: opts.envelopeId,
    workflowId: opts.workflowId,
    labels: new Set(opts.labels ?? []),
    aggregateSensitivity: opts.aggregateSensitivity ?? DataClassification.PUBLIC,
    restrictions: new Set(opts.restrictions ?? []),
    version: opts.version ?? 0,
    parentEnvelopeId: opts.parentEnvelopeId ?? null,
    createdAt: opts.createdAt ?? '',
  };
}

/** Return the next version of env with new_labels and new_sensitivity folded in.
 * Pure join: labels are unioned, sensitivity is the lattice max. */
export function fold(
  env: ContextEnvelope,
  newLabels: Iterable<string>,
  newSensitivity: DataClassification,
): ContextEnvelope {
  const joinedLabels = new Set([...env.labels, ...newLabels]);
  const joinedSensitivity = Math.max(env.aggregateSensitivity, newSensitivity) as DataClassification;
  return {
    ...env,
    labels: joinedLabels,
    aggregateSensitivity: joinedSensitivity,
    version: env.version + 1,
  };
}

/** Return the next version of env with restrictions added (grow-only). */
export function applyRestrictions(
  env: ContextEnvelope,
  restrictions: Iterable<string>,
): ContextEnvelope {
  const grown = new Set([...env.restrictions, ...restrictions]);
  return { ...env, restrictions: grown, version: env.version + 1 };
}

/** Opaque, cross-boundary handle to a ContextEnvelope. Carries only the id and coarse sensitivity. */
export interface EnvelopeReference {
  readonly envelopeId: string;
  readonly sensitivity: DataClassification;
}

/** Project env onto its opaque cross-boundary reference. */
export function envelopeReference(env: ContextEnvelope): EnvelopeReference {
  return { envelopeId: env.envelopeId, sensitivity: env.aggregateSensitivity };
}

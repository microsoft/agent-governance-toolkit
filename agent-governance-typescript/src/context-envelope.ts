// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { requireIdentifier, snapshotTokens, unionTokens } from './context-tokens';
import {
  DataClassification,
  maximumClassification,
  requireDataClassification,
} from './data-classification';

/**
 * Accumulated governance state for a workflow.
 *
 * Ported from the Python reference (`agent_os/policies/context_envelope.py`).
 *
 * A `ContextEnvelope` is an immutable, versioned value holding the labels seen so
 * far, a running-max sensitivity and a grow-only set of restriction tokens. Label
 * union is commutative and idempotent and sensitivity only ever rises, so a
 * single-writer can fold deltas in any order and land on the same state.
 */

/** Fields accepted by the {@link ContextEnvelope} constructor. */
export interface ContextEnvelopeInit {
  /** Stable identifier for this envelope's lineage. */
  envelopeId: string;
  /** Correlation key: a workflow spans tool calls and delegations. */
  workflowId: string;
  /** Accumulated labels. */
  labels?: Iterable<string>;
  /** Running-max sensitivity. Defaults to `DataClassification.Public`. */
  aggregateSensitivity?: DataClassification;
  /** Grow-only restriction tokens. */
  restrictions?: Iterable<string>;
  /** Monotonic version. Every fold or restriction application yields `version + 1`. */
  version?: number;
  /** Set on an envelope a parent delegated to. */
  parentEnvelopeId?: string | null;
  /** Caller-supplied timestamp; nothing here reads the clock. */
  createdAt?: string;
}

/** Immutable, versioned accumulation of workflow governance state. */
export class ContextEnvelope {
  readonly envelopeId: string;
  readonly workflowId: string;
  readonly labels: ReadonlySet<string>;
  readonly aggregateSensitivity: DataClassification;
  readonly restrictions: ReadonlySet<string>;
  readonly version: number;
  readonly parentEnvelopeId: string | null;
  readonly createdAt: string;

  constructor(init: ContextEnvelopeInit) {
    this.envelopeId = requireIdentifier(init.envelopeId, 'envelopeId');
    this.workflowId = requireIdentifier(init.workflowId, 'workflowId');
    this.labels = snapshotTokens(init.labels, 'labels');
    this.aggregateSensitivity = requireDataClassification(
      init.aggregateSensitivity ?? DataClassification.Public,
      'aggregateSensitivity',
    );
    this.restrictions = snapshotTokens(init.restrictions, 'restrictions');

    const version = init.version ?? 0;
    if (!Number.isSafeInteger(version) || version < 0) {
      throw new RangeError(
        `version must be a non-negative safe integer, received ${String(version)}.`,
      );
    }
    this.version = version;
    this.parentEnvelopeId = init.parentEnvelopeId ?? null;
    this.createdAt = init.createdAt ?? '';
  }

  /**
   * The next version of this envelope with `newLabels` joined in and
   * `newSensitivity` folded into the running max.
   *
   * Restrictions are left alone: they are derived by aggregation and applied
   * through {@link applyRestrictions}.
   */
  fold(newLabels: Iterable<string>, newSensitivity: DataClassification): ContextEnvelope {
    return this.copy({
      labels: unionTokens(this.labels, newLabels, 'newLabels'),
      aggregateSensitivity: maximumClassification(
        this.aggregateSensitivity,
        requireDataClassification(newSensitivity, 'newSensitivity'),
      ),
      version: this.version + 1,
    });
  }

  /** The next version of this envelope with `restrictions` added (grow-only). */
  applyRestrictions(restrictions: Iterable<string>): ContextEnvelope {
    return this.copy({
      restrictions: unionTokens(this.restrictions, restrictions, 'restrictions'),
      version: this.version + 1,
    });
  }

  /** Projects this envelope onto its opaque cross-boundary reference. */
  reference(): EnvelopeReference {
    return new EnvelopeReference(this.envelopeId, this.aggregateSensitivity);
  }

  /**
   * The same version with `sensitivity` as its aggregate sensitivity.
   *
   * Used by `accumulate` to adopt the sensitivity the aggregation computed from the
   * labels it just folded. The fold already counted the version, so this must not
   * count a second time.
   */
  withAggregateSensitivity(sensitivity: DataClassification): ContextEnvelope {
    return this.copy({
      aggregateSensitivity: requireDataClassification(sensitivity, 'sensitivity'),
    });
  }

  private copy(changes: {
    labels?: Iterable<string>;
    aggregateSensitivity?: DataClassification;
    restrictions?: Iterable<string>;
    version?: number;
  }): ContextEnvelope {
    return new ContextEnvelope({
      envelopeId: this.envelopeId,
      workflowId: this.workflowId,
      labels: changes.labels ?? this.labels,
      aggregateSensitivity: changes.aggregateSensitivity ?? this.aggregateSensitivity,
      restrictions: changes.restrictions ?? this.restrictions,
      version: changes.version ?? this.version,
      parentEnvelopeId: this.parentEnvelopeId,
      createdAt: this.createdAt,
    });
  }
}

/**
 * An opaque handle to a `ContextEnvelope` for values that cross a trust boundary.
 *
 * It carries the lineage id and the coarse sensitivity tier only, and deliberately
 * omits labels, restrictions, version and timestamps, so a consumer has to resolve
 * the envelope through its issuer instead of pinning its shape.
 */
export class EnvelopeReference {
  readonly envelopeId: string;
  readonly sensitivity: DataClassification;

  constructor(envelopeId: string, sensitivity: DataClassification) {
    this.envelopeId = requireIdentifier(envelopeId, 'envelopeId');
    this.sensitivity = requireDataClassification(sensitivity, 'sensitivity');
  }
}

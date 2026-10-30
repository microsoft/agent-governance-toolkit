// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { requireIdentifier, snapshotTokens } from './context-tokens';

/**
 * Obligations carried by a `constrain` outcome.
 *
 * Ported from the Python reference (`agent_os/policies/obligations.py`).
 *
 * `constrain` is allow-with-obligations: the action may proceed when the host can
 * carry these restrictions forward, or when every obligation is already satisfied.
 * A host with no obligation channel has to fail closed.
 */

/** Fields accepted by the {@link Obligation} constructor. */
export interface ObligationInit {
  /** The restriction the host must honour. */
  key: string;
  /** Whether the caller already declared the restriction satisfied. Defaults to false. */
  satisfied?: boolean;
}

/** A single restriction the host must honour for an action to proceed. */
export class Obligation {
  readonly key: string;
  readonly satisfied: boolean;

  constructor(init: ObligationInit) {
    this.key = requireIdentifier(init.key, 'key');
    this.satisfied = init.satisfied ?? false;
  }
}

/** Fields accepted by the {@link ObligationSet} constructor. */
export interface ObligationSetInit {
  obligations?: Iterable<Obligation>;
  /** Labels the caller must carry forward with the action. */
  resultLabels?: Iterable<string>;
}

/** The obligations and labels a `constrain` outcome carries forward. */
export class ObligationSet {
  readonly obligations: readonly Obligation[];
  readonly resultLabels: ReadonlySet<string>;

  constructor(init: ObligationSetInit = {}) {
    this.obligations = [...(init.obligations ?? [])];
    this.resultLabels = snapshotTokens(init.resultLabels, 'resultLabels');
  }

  /** True when every obligation is already satisfied. An empty set is vacuously satisfied. */
  allSatisfied(): boolean {
    return this.obligations.every((obligation) => obligation.satisfied);
  }
}

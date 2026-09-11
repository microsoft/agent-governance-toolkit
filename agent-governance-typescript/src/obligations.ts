// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Obligations carried by a `constrain` governance outcome.
 *
 * In Context Accumulation Governance, `constrain` is allow-with-obligations:
 * the action is permitted only if the host can carry restrictions forward
 * (an obligation channel), or every obligation is already satisfied.
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/obligations.py.
 * Refs #3084.
 */

/** A single restriction the host must honor for an action to proceed. */
export interface Obligation {
  readonly key: string;
  readonly satisfied: boolean;
}

/** The obligations and labels a `constrain` outcome carries forward. */
export interface ObligationSet {
  readonly obligations: readonly Obligation[];
  readonly resultLabels: ReadonlySet<string>;
}

/** True iff every obligation is already declaratively satisfied. */
export function allSatisfied(os: ObligationSet): boolean {
  return os.obligations.every((o) => o.satisfied);
}

export function makeObligationSet(
  opts: { obligations?: readonly Obligation[]; resultLabels?: Iterable<string> } = {},
): ObligationSet {
  return {
    obligations: opts.obligations ?? [],
    resultLabels: new Set(opts.resultLabels ?? []),
  };
}

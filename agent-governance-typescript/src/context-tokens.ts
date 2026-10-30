// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Validation and copy helpers shared by the accumulated-context value types.
 *
 * Labels and restriction tokens are the join keys of the whole model: they are
 * compared for set membership when aggregation rules fire. A token that is not a
 * string (`undefined` from a bad map lookup, say) compares unequal to every rule
 * and the escalation backstop never fires, so the types below never accept one.
 */

const ownSnapshots = new WeakSet<object>();

/**
 * A copy of `tokens` for a value type to own. Tokens are copied verbatim — normalization is
 * the caller's decision and this layer never rewrites a token the caller owns.
 *
 * A set this module already produced is passed through rather than copied again: copying an
 * unchanged field on every derived value made `accumulate` quadratic (three copies per step;
 * 20k sequential steps took ~2 minutes). Sets reaching here from outside are still copied.
 *
 * The sets a value type exposes are shared, not isolated. An envelope getter hands back the
 * same object a derived value may hold, so `ReadonlySet` is a contract the caller keeps rather
 * than a guarantee this module enforces: do not mutate one. It is a compile-time type only, and
 * a JavaScript caller can still call `add` on what it gets back. (Freezing would not help — a
 * Set keeps its members in internal slots, so `Object.freeze` leaves `add` working.)
 *
 * `undefined` yields a fresh empty set rather than one shared instance, so that the empty case
 * at least does not put every envelope behind a single object.
 */
export function snapshotTokens(
  tokens: Iterable<string> | undefined,
  parameterName: string,
): ReadonlySet<string> {
  if (tokens === undefined) {
    const empty = new Set<string>();
    ownSnapshots.add(empty);
    return empty;
  }
  if (ownSnapshots.has(tokens)) {
    return tokens as ReadonlySet<string>;
  }
  const snapshot = new Set<string>();
  for (const token of tokens) {
    if (typeof token !== 'string') {
      throw new TypeError(`${parameterName} must contain only strings.`);
    }
    snapshot.add(token);
  }
  ownSnapshots.add(snapshot);
  return snapshot;
}

/** A non-empty identifier with no leading or trailing whitespace. */
export function requireIdentifier(value: string, parameterName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${parameterName} must be a non-empty string.`);
  }
  if (value !== value.trim()) {
    throw new TypeError(`${parameterName} must not contain leading or trailing whitespace.`);
  }
  return value;
}

/** Grow-only union: a token already in `existing` is never dropped. */
export function unionTokens(
  existing: Iterable<string>,
  added: Iterable<string> | undefined,
  parameterName: string,
): ReadonlySet<string> {
  return snapshotTokens([...existing, ...(added ?? [])], parameterName);
}

/** Members of `left` that are not in `right`. */
export function differenceTokens(
  left: ReadonlySet<string>,
  right: ReadonlySet<string>,
): ReadonlySet<string> {
  const difference = new Set<string>();
  for (const token of left) {
    if (!right.has(token)) {
      difference.add(token);
    }
  }
  return difference;
}

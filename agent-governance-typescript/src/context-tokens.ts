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

const NO_TOKENS: ReadonlySet<string> = new Set<string>();

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

/**
 * A private copy of `tokens`. Tokens are copied verbatim — normalization is the
 * caller's decision and this layer never rewrites a token the caller owns.
 */
export function snapshotTokens(
  tokens: Iterable<string> | undefined,
  parameterName: string,
): ReadonlySet<string> {
  if (tokens === undefined) {
    return NO_TOKENS;
  }
  const snapshot = new Set<string>();
  for (const token of tokens) {
    if (typeof token !== 'string') {
      throw new TypeError(`${parameterName} must contain only strings.`);
    }
    snapshot.add(token);
  }
  return snapshot;
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

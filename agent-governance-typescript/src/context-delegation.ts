// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { ContextEnvelope } from './context-envelope';
import { unionTokens } from './context-tokens';

/**
 * Restriction inheritance across a delegation boundary.
 *
 * Ported from the Python reference (`agent_os/policies/context_delegation.py`).
 *
 * When a workflow delegates to a child agent, the child inherits the parent's
 * restrictions: a child may add a restriction but never drop one.
 */

/** The child's effective restrictions: parent union child-declared. Grow-only. */
export function mergeRestrictions(
  parent: ContextEnvelope,
  childDeclared: Iterable<string>,
): ReadonlySet<string> {
  return unionTokens(parent.restrictions, childDeclared, 'childDeclared');
}

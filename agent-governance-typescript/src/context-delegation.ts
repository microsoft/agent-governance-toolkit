// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Restriction inheritance across a delegation boundary.
 *
 * When a workflow delegates to a child agent, the child's context envelope must
 * inherit the parent's restrictions: a delegatee may ADD restrictions but never
 * DROP one. This is a pure, grow-only union.
 *
 * Parity with agent-governance-python agent-os/src/agent_os/policies/context_delegation.py.
 * Refs #3084.
 */

import type { ContextEnvelope } from './context-envelope';

/** Return the child's effective restrictions: parent ∪ child-declared. */
export function mergeRestrictions(
  parent: ContextEnvelope,
  childDeclared: Iterable<string>,
): Set<string> {
  return new Set([...parent.restrictions, ...childDeclared]);
}

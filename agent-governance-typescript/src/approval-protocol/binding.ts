// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Action binding for the action-bound approval protocol (ADR-0030 section 2).
 *
 * An ActionBinding captures the exact executable request an approval authorizes.
 * Its actionDigest is the SHA-256 over the JCS serialization of the binding,
 * so an approval for one binding can never authorize a different action.
 *
 * Parity with agent-governance-python
 * agent-mesh/src/agentmesh/governance/approval_protocol/binding.py.
 * Refs #3083.
 */

import { sha256Jcs } from './digest';

export const SCHEMA_VERSION = '1.0';

export interface ActionTarget {
  readonly toolName: string;
  readonly toolSchemaVersion: string;
  readonly resource: string | null;
}

export function makeActionTarget(
  opts: Pick<ActionTarget, 'toolName' | 'toolSchemaVersion'> &
    Partial<Pick<ActionTarget, 'resource'>>,
): ActionTarget {
  return { resource: null, ...opts };
}

function targetToCanonical(target: ActionTarget): Record<string, unknown> {
  return {
    tool_name: target.toolName,
    tool_schema_version: target.toolSchemaVersion,
    resource: target.resource,
  };
}

export interface ActionBinding {
  readonly operation: string;
  readonly agentId: string;
  readonly target: ActionTarget;
  readonly parameters: Record<string, unknown>;
  readonly subjectId: string | null;
  readonly schemaVersion: string;
}

export function makeActionBinding(
  opts: Pick<ActionBinding, 'operation' | 'agentId' | 'target'> & {
    parameters?: Record<string, unknown>;
    subjectId?: string | null;
    schemaVersion?: string;
  },
): ActionBinding {
  return {
    parameters: {},
    subjectId: null,
    schemaVersion: SCHEMA_VERSION,
    ...opts,
  };
}

export function bindingToCanonical(binding: ActionBinding): Record<string, unknown> {
  return {
    schema_version: binding.schemaVersion,
    operation: binding.operation,
    agent_id: binding.agentId,
    subject_id: binding.subjectId,
    target: targetToCanonical(binding.target),
    parameters: binding.parameters,
  };
}

export function bindingDigest(binding: ActionBinding): string {
  return sha256Jcs(bindingToCanonical(binding));
}

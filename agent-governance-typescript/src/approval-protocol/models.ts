// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Protocol objects for the action-bound approval protocol (ADR-0030 section 3).
 *
 * Parity with agent-governance-python
 * agent-mesh/src/agentmesh/governance/approval_protocol/models.py.
 * Refs #3083.
 */

import { randomUUID } from 'crypto';
import { sha256Jcs } from './digest';

export function utcnow(): Date {
  return new Date();
}

function newId(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/g, '')}`;
}

/** Canonical policy enforcement outcomes (ADR-0030 section 1). */
export type Verdict = 'allow' | 'deny' | 'require_approval';

/** Lifecycle state of an ApprovalRequest. */
export type ApprovalStatus =
  | 'pending'
  | 'allowed'
  | 'denied'
  | 'expired'
  | 'cancelled'
  | 'consumed';

/** Kind of principal recorded on a chain entry. */
export type ApproverKind = 'human' | 'service' | 'llm_advisory';

/** An individual approver's vote on a chain entry. */
export type EntryDecision = 'allow' | 'deny';

/** Terminal resolution outcome of an approval request. */
export type Outcome = 'allow' | 'deny' | 'expired';

export interface PolicyDecisionRecord {
  readonly actionDigest: string;
  readonly policyRuleId: string;
  readonly policyVersion: string;
  readonly approvalChainId: string;
  readonly approvalChainVersion: string;
  readonly verdict: Verdict;
  readonly policyDecisionId: string;
  readonly decidedAt: Date;
}

export function makePolicyDecisionRecord(
  opts: Pick<
    PolicyDecisionRecord,
    'actionDigest' | 'policyRuleId' | 'policyVersion' | 'approvalChainId' | 'approvalChainVersion'
  >,
): PolicyDecisionRecord {
  return {
    verdict: 'require_approval',
    policyDecisionId: newId('pd'),
    decidedAt: utcnow(),
    ...opts,
  };
}

export interface ApprovalRequest {
  readonly policyDecisionId: string;
  readonly actionDigest: string;
  readonly agentId: string;
  readonly operation: string;
  readonly policyVersion: string;
  readonly approvalChainId: string;
  readonly approvalChainVersion: string;
  readonly expiresAt: Date;
  readonly subjectId: string | null;
  readonly targetResource: string | null;
  readonly failClosedOnTimeout: boolean;
  status: ApprovalStatus;
  readonly approvalRequestId: string;
  readonly requestedAt: Date;
}

export function makeApprovalRequest(
  opts: Omit<ApprovalRequest, 'status' | 'approvalRequestId' | 'requestedAt' | 'subjectId' | 'targetResource' | 'failClosedOnTimeout'> &
    Partial<Pick<ApprovalRequest, 'subjectId' | 'targetResource' | 'failClosedOnTimeout'>>,
): ApprovalRequest {
  return {
    subjectId: null,
    targetResource: null,
    failClosedOnTimeout: true,
    status: 'pending',
    approvalRequestId: newId('ar'),
    requestedAt: utcnow(),
    ...opts,
  };
}

export function presentedCanonical(request: ApprovalRequest): Record<string, unknown> {
  return {
    approval_request_id: request.approvalRequestId,
    policy_decision_id: request.policyDecisionId,
    action_digest: request.actionDigest,
    agent_id: request.agentId,
    subject_id: request.subjectId,
    operation: request.operation,
    target_resource: request.targetResource,
    policy_version: request.policyVersion,
    approval_chain_id: request.approvalChainId,
    approval_chain_version: request.approvalChainVersion,
    expires_at: request.expiresAt.toISOString(),
  };
}

export function inputDigest(request: ApprovalRequest): string {
  return sha256Jcs(presentedCanonical(request));
}

export interface ApprovalChainEntry {
  readonly approvalRequestId: string;
  readonly stageIndex: number;
  readonly approverKind: ApproverKind;
  readonly approverIdentity: string;
  readonly identityAssurance: string;
  readonly decision: EntryDecision;
  readonly inputDigest: string;
  readonly reasonCode: string;
  readonly previousEntryDigest: string | null;
  readonly chainEntryId: string;
  readonly decidedAt: Date;
  entryDigest: string | null;
}

export function makeApprovalChainEntry(
  opts: Omit<ApprovalChainEntry, 'chainEntryId' | 'decidedAt' | 'entryDigest' | 'reasonCode' | 'previousEntryDigest'> &
    Partial<Pick<ApprovalChainEntry, 'chainEntryId' | 'reasonCode' | 'previousEntryDigest'>>,
): ApprovalChainEntry {
  return {
    reasonCode: '',
    previousEntryDigest: null,
    chainEntryId: newId('ace'),
    decidedAt: utcnow(),
    entryDigest: null,
    ...opts,
  };
}

function canonicalWithoutDigest(entry: ApprovalChainEntry): Record<string, unknown> {
  return {
    approval_request_id: entry.approvalRequestId,
    chain_entry_id: entry.chainEntryId,
    stage_index: entry.stageIndex,
    approver_kind: entry.approverKind,
    approver_identity: entry.approverIdentity,
    identity_assurance: entry.identityAssurance,
    decision: entry.decision,
    reason_code: entry.reasonCode,
    input_digest: entry.inputDigest,
    previous_entry_digest: entry.previousEntryDigest,
    decided_at: entry.decidedAt.toISOString(),
  };
}

export function computeEntryDigest(entry: ApprovalChainEntry): string {
  return sha256Jcs(canonicalWithoutDigest(entry));
}

export function sealEntry(entry: ApprovalChainEntry): ApprovalChainEntry {
  entry.entryDigest = computeEntryDigest(entry);
  return entry;
}

export function verifyEntryDigest(entry: ApprovalChainEntry): boolean {
  return entry.entryDigest !== null && entry.entryDigest === computeEntryDigest(entry);
}

export interface ApprovalResolution {
  readonly approvalRequestId: string;
  readonly outcome: Outcome;
  readonly actionDigest: string;
  readonly policyVersion: string;
  readonly approvalChainVersion: string;
  readonly finalEntryDigest: string | null;
  readonly approvalResolutionId: string;
  readonly resolvedAt: Date;
}

export function makeApprovalResolution(
  opts: Omit<ApprovalResolution, 'approvalResolutionId' | 'resolvedAt'>,
): ApprovalResolution {
  return {
    approvalResolutionId: newId('apr'),
    resolvedAt: utcnow(),
    ...opts,
  };
}

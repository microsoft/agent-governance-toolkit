// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Approval coordinator for the action-bound approval protocol (ADR-0030).
 *
 * The coordinator owns the approval lifecycle:
 * - openRequest: turns a require_approval policy decision into a durable,
 *   action-bound ApprovalRequest
 * - submitEntry: records an authenticated, hash-linked approver decision
 * - validateForExecution: atomic pre-execution revalidation (ADR-0030 section 6)
 *
 * Every failure path is fail-closed: anything that is not an unambiguous
 * terminal allow over the exact action, policy version, and chain version
 * denies execution and returns a machine-readable reason code.
 *
 * Parity with agent-governance-python
 * agent-mesh/src/agentmesh/governance/approval_protocol/coordinator.py.
 * Refs #3083.
 */

import type { ActionBinding } from './binding';
import { bindingDigest } from './binding';
import {
  type ApprovalChainEntry,
  type ApprovalRequest,
  type ApprovalResolution,
  type ApproverKind,
  type EntryDecision,
  type Outcome,
  type PolicyDecisionRecord,
  computeEntryDigest,
  inputDigest,
  makeApprovalChainEntry,
  makeApprovalRequest,
  makeApprovalResolution,
  makePolicyDecisionRecord,
  sealEntry,
  utcnow,
  verifyEntryDigest,
} from './models';
import type { ApprovalStore } from './store';

export class ApprovalProtocolError extends Error {}

export const ReasonCode = {
  OK: 'ok',
  UNKNOWN_REQUEST: 'unknown_request',
  NO_RESOLUTION: 'no_resolution',
  NOT_TERMINAL_ALLOW: 'not_terminal_allow',
  EXPIRED: 'expired',
  CANCELLED: 'cancelled',
  ALREADY_CONSUMED: 'already_consumed',
  ACTION_DIGEST_MISMATCH: 'action_digest_mismatch',
  POLICY_VERSION_MISMATCH: 'policy_version_mismatch',
  CHAIN_VERSION_MISMATCH: 'chain_version_mismatch',
  CHAIN_TAMPERED: 'chain_tampered',
  INTERNAL_ERROR: 'internal_error',
} as const;

export interface ExecutionDecision {
  readonly allowed: boolean;
  readonly reasonCode: string;
}

/** One ordered stage of an approval chain. */
export interface ApprovalStage {
  readonly stageIndex: number;
  readonly allowedIdentities: ReadonlySet<string>;
  readonly allowedRoles: ReadonlySet<string>;
  readonly required: boolean;
}

export function makeApprovalStage(
  opts: Pick<ApprovalStage, 'stageIndex'> & {
    allowedIdentities?: Iterable<string>;
    allowedRoles?: Iterable<string>;
    required?: boolean;
  },
): ApprovalStage {
  return {
    allowedIdentities: new Set(opts.allowedIdentities ?? []),
    allowedRoles: new Set(opts.allowedRoles ?? []),
    required: opts.required ?? true,
    stageIndex: opts.stageIndex,
  };
}

export function stageAuthorizes(
  stage: ApprovalStage,
  identity: string,
  roles: Iterable<string>,
): boolean {
  if (stage.allowedIdentities.has(identity)) return true;
  for (const role of roles) {
    if (stage.allowedRoles.has(role)) return true;
  }
  return false;
}

/** A versioned, immutable approval-chain configuration. */
export interface ApprovalChain {
  readonly chainId: string;
  readonly version: string;
  readonly stages: readonly ApprovalStage[];
}

export function getStage(chain: ApprovalChain, stageIndex: number): ApprovalStage | null {
  return chain.stages.find((s) => s.stageIndex === stageIndex) ?? null;
}

/** Creates, advances, and validates action-bound approval requests. */
export class ApprovalCoordinator {
  constructor(
    private readonly store: ApprovalStore,
    private readonly chains: Map<string, ApprovalChain>,
    private readonly clock: () => Date = utcnow,
  ) {}

  openRequest(
    binding: ActionBinding,
    opts: {
      policyRuleId: string;
      policyVersion: string;
      chainId: string;
      ttlSeconds: number;
      targetResource?: string | null;
      failClosedOnTimeout?: boolean;
    },
  ): { decision: PolicyDecisionRecord; request: ApprovalRequest } {
    const chain = this.chains.get(opts.chainId);
    if (!chain) throw new ApprovalProtocolError(`unknown approval chain: ${opts.chainId}`);

    const actionDigest = bindingDigest(binding);
    const decision = makePolicyDecisionRecord({
      actionDigest,
      policyRuleId: opts.policyRuleId,
      policyVersion: opts.policyVersion,
      approvalChainId: chain.chainId,
      approvalChainVersion: chain.version,
    });
    const now = this.clock();
    const expiresAt = new Date(now.getTime() + opts.ttlSeconds * 1000);
    const request = makeApprovalRequest({
      policyDecisionId: decision.policyDecisionId,
      actionDigest,
      agentId: binding.agentId,
      operation: binding.operation,
      policyVersion: opts.policyVersion,
      approvalChainId: chain.chainId,
      approvalChainVersion: chain.version,
      expiresAt,
      subjectId: binding.subjectId,
      targetResource:
        opts.targetResource !== undefined ? opts.targetResource : binding.target.resource,
      failClosedOnTimeout: opts.failClosedOnTimeout ?? true,
    });
    this.store.saveRequest(request);
    return { decision, request };
  }

  submitEntry(
    approvalRequestId: string,
    opts: {
      stageIndex: number;
      approverKind: ApproverKind;
      approverIdentity: string;
      identityAssurance: string;
      decision: EntryDecision;
      reasonCode?: string;
      roles?: Iterable<string>;
      chainEntryId?: string;
    },
  ): ApprovalChainEntry {
    const request = this.store.getRequest(approvalRequestId);
    if (!request) throw new ApprovalProtocolError(`unknown approval request: ${approvalRequestId}`);

    // Idempotent resubmission by caller-supplied chainEntryId.
    if (opts.chainEntryId !== undefined) {
      for (const existing of this.store.getEntries(approvalRequestId)) {
        if (existing.chainEntryId === opts.chainEntryId) return existing;
      }
    }

    if (this._expireIfDue(request)) throw new ApprovalProtocolError('approval request has expired');
    if (request.status !== 'pending') {
      throw new ApprovalProtocolError(
        `approval request is not pending (status=${request.status})`,
      );
    }

    const chain = this.chains.get(request.approvalChainId)!;
    const stage = getStage(chain, opts.stageIndex);
    if (!stage) throw new ApprovalProtocolError(`unknown stage index: ${opts.stageIndex}`);

    const isAdvisory = opts.approverKind === 'llm_advisory';
    if (
      !isAdvisory &&
      !stageAuthorizes(stage, opts.approverIdentity, opts.roles ?? [])
    ) {
      throw new ApprovalProtocolError(
        `identity ${opts.approverIdentity} not permitted for stage ${opts.stageIndex}`,
      );
    }

    const prior = this.store.getEntries(approvalRequestId);
    const previousDigest = prior.length > 0 ? prior[prior.length - 1].entryDigest : null;
    const entry = sealEntry(
      makeApprovalChainEntry({
        approvalRequestId,
        stageIndex: opts.stageIndex,
        approverKind: opts.approverKind,
        approverIdentity: opts.approverIdentity,
        identityAssurance: opts.identityAssurance,
        decision: opts.decision,
        inputDigest: inputDigest(request),
        reasonCode: opts.reasonCode ?? '',
        previousEntryDigest: previousDigest,
        ...(opts.chainEntryId !== undefined ? { chainEntryId: opts.chainEntryId } : {}),
      }),
    );

    this.store.appendEntry(entry);
    if (!isAdvisory) {
      this._maybeResolve(request, chain);
    }
    return entry;
  }

  validateForExecution(
    approvalRequestId: string,
    opts: {
      currentActionDigest: string;
      currentPolicyVersion: string;
      currentChainVersion: string;
      consume?: boolean;
    },
  ): ExecutionDecision {
    try {
      const request = this.store.getRequest(approvalRequestId);
      if (!request) return { allowed: false, reasonCode: ReasonCode.UNKNOWN_REQUEST };

      this._expireIfDue(request);

      const resolution = this.store.getResolution(approvalRequestId);
      if (!resolution) return { allowed: false, reasonCode: ReasonCode.NO_RESOLUTION };
      if (resolution.outcome === 'expired') return { allowed: false, reasonCode: ReasonCode.EXPIRED };
      if (resolution.outcome !== 'allow') return { allowed: false, reasonCode: ReasonCode.NOT_TERMINAL_ALLOW };

      if (request.status === 'consumed') return { allowed: false, reasonCode: ReasonCode.ALREADY_CONSUMED };
      if (request.status === 'cancelled') return { allowed: false, reasonCode: ReasonCode.CANCELLED };
      if (request.status !== 'allowed') return { allowed: false, reasonCode: ReasonCode.NOT_TERMINAL_ALLOW };

      if (this.clock() >= request.expiresAt) return { allowed: false, reasonCode: ReasonCode.EXPIRED };

      if (opts.currentActionDigest !== resolution.actionDigest) {
        return { allowed: false, reasonCode: ReasonCode.ACTION_DIGEST_MISMATCH };
      }
      if (opts.currentPolicyVersion !== resolution.policyVersion) {
        return { allowed: false, reasonCode: ReasonCode.POLICY_VERSION_MISMATCH };
      }
      if (opts.currentChainVersion !== resolution.approvalChainVersion) {
        return { allowed: false, reasonCode: ReasonCode.CHAIN_VERSION_MISMATCH };
      }

      if (!this._chainIntact(approvalRequestId, resolution.finalEntryDigest)) {
        return { allowed: false, reasonCode: ReasonCode.CHAIN_TAMPERED };
      }

      if ((opts.consume ?? true) && !this.store.consume(approvalRequestId)) {
        return { allowed: false, reasonCode: ReasonCode.ALREADY_CONSUMED };
      }

      return { allowed: true, reasonCode: ReasonCode.OK };
    } catch {
      return { allowed: false, reasonCode: ReasonCode.INTERNAL_ERROR };
    }
  }

  private _expireIfDue(request: ApprovalRequest): boolean {
    if (request.status !== 'pending') return request.status === 'expired';
    if (this.clock() >= request.expiresAt) {
      this._resolve(request, 'expired', null);
      return true;
    }
    return false;
  }

  private _maybeResolve(request: ApprovalRequest, chain: ApprovalChain): void {
    if (this.store.getResolution(request.approvalRequestId) !== null) return;

    const required = new Set(chain.stages.filter((s) => s.required).map((s) => s.stageIndex));
    // A chain with zero required stages is misconfigured: deny immediately rather
    // than vacuously allowing (fail-closed semantics, mirrors Go port in #3242).
    if (required.size === 0) {
      this._resolve(request, 'deny', null);
      return;
    }

    const entries = this.store
      .getEntries(request.approvalRequestId)
      .filter((e) => e.approverKind !== 'llm_advisory');

    for (const entry of entries) {
      if (entry.decision === 'deny') {
        this._resolve(request, 'deny', entry.entryDigest);
        return;
      }
    }

    const allowedStages = new Set(
      entries.filter((e) => e.decision === 'allow').map((e) => e.stageIndex),
    );
    if ([...required].every((idx) => allowedStages.has(idx))) {
      const finalDigest = entries.length > 0 ? entries[entries.length - 1].entryDigest : null;
      this._resolve(request, 'allow', finalDigest);
    }
  }

  private _resolve(
    request: ApprovalRequest,
    outcome: Outcome,
    finalEntryDigest: string | null,
  ): ApprovalResolution {
    const resolution = makeApprovalResolution({
      approvalRequestId: request.approvalRequestId,
      outcome,
      actionDigest: request.actionDigest,
      policyVersion: request.policyVersion,
      approvalChainVersion: request.approvalChainVersion,
      finalEntryDigest,
    });
    this.store.saveResolution(resolution);
    const statusMap: Record<Outcome, 'allowed' | 'denied' | 'expired'> = {
      allow: 'allowed',
      deny: 'denied',
      expired: 'expired',
    };
    this.store.setStatus(request.approvalRequestId, statusMap[outcome]);
    return resolution;
  }

  private _chainIntact(
    approvalRequestId: string,
    finalEntryDigest: string | null,
  ): boolean {
    const entries = this.store.getEntries(approvalRequestId);
    let previous: string | null = null;
    for (const entry of entries) {
      if (!verifyEntryDigest(entry)) return false;
      if (entry.previousEntryDigest !== previous) return false;
      previous = entry.entryDigest;
    }
    if (finalEntryDigest !== null && previous !== finalEntryDigest) return false;
    return true;
  }
}

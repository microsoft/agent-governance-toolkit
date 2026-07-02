// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Durable store contract for pending approvals (ADR-0030 section 5).
 *
 * ApprovalStore is the protocol production deployments implement against a real
 * backend; InMemoryApprovalStore is a reference implementation for tests and
 * single-process embedders. Node.js is single-threaded so no mutex is needed.
 *
 * Parity with agent-governance-python
 * agent-mesh/src/agentmesh/governance/approval_protocol/store.py.
 * Refs #3083.
 */

import type {
  ApprovalChainEntry,
  ApprovalRequest,
  ApprovalResolution,
  ApprovalStatus,
} from './models';

export interface ApprovalStore {
  saveRequest(request: ApprovalRequest): void;
  getRequest(approvalRequestId: string): ApprovalRequest | null;
  setStatus(approvalRequestId: string, status: ApprovalStatus): void;
  appendEntry(entry: ApprovalChainEntry): void;
  getEntries(approvalRequestId: string): ApprovalChainEntry[];
  saveResolution(resolution: ApprovalResolution): void;
  getResolution(approvalRequestId: string): ApprovalResolution | null;
  /** Atomically mark an ALLOWED request CONSUMED. Returns true exactly once. */
  consume(approvalRequestId: string): boolean;
}

export class InMemoryApprovalStore implements ApprovalStore {
  private _requests = new Map<string, ApprovalRequest>();
  private _entries = new Map<string, ApprovalChainEntry[]>();
  private _resolutions = new Map<string, ApprovalResolution>();

  saveRequest(request: ApprovalRequest): void {
    this._requests.set(request.approvalRequestId, request);
    if (!this._entries.has(request.approvalRequestId)) {
      this._entries.set(request.approvalRequestId, []);
    }
  }

  getRequest(approvalRequestId: string): ApprovalRequest | null {
    return this._requests.get(approvalRequestId) ?? null;
  }

  setStatus(approvalRequestId: string, status: ApprovalStatus): void {
    const req = this._requests.get(approvalRequestId);
    if (req) req.status = status;
  }

  appendEntry(entry: ApprovalChainEntry): void {
    const list = this._entries.get(entry.approvalRequestId);
    if (list) list.push(entry);
    else this._entries.set(entry.approvalRequestId, [entry]);
  }

  getEntries(approvalRequestId: string): ApprovalChainEntry[] {
    return [...(this._entries.get(approvalRequestId) ?? [])];
  }

  saveResolution(resolution: ApprovalResolution): void {
    this._resolutions.set(resolution.approvalRequestId, resolution);
  }

  getResolution(approvalRequestId: string): ApprovalResolution | null {
    return this._resolutions.get(approvalRequestId) ?? null;
  }

  consume(approvalRequestId: string): boolean {
    const req = this._requests.get(approvalRequestId);
    if (!req || req.status !== 'allowed') return false;
    req.status = 'consumed';
    return true;
  }
}

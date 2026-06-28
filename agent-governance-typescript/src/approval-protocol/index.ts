// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { canonicalize, sha256Jcs, DIGEST_PREFIX } from './digest';
export {
  makeActionTarget,
  makeActionBinding,
  bindingToCanonical,
  bindingDigest,
  SCHEMA_VERSION,
} from './binding';
export type { ActionTarget, ActionBinding } from './binding';
export {
  utcnow,
  makePolicyDecisionRecord,
  makeApprovalRequest,
  presentedCanonical,
  inputDigest,
  makeApprovalChainEntry,
  computeEntryDigest,
  sealEntry,
  verifyEntryDigest,
  makeApprovalResolution,
} from './models';
export type {
  Verdict,
  ApprovalStatus,
  ApproverKind,
  EntryDecision,
  Outcome,
  PolicyDecisionRecord,
  ApprovalRequest,
  ApprovalChainEntry,
  ApprovalResolution,
} from './models';
export { InMemoryApprovalStore } from './store';
export type { ApprovalStore } from './store';
export {
  ApprovalProtocolError,
  ApprovalCoordinator,
  ReasonCode,
  makeApprovalStage,
  stageAuthorizes,
  getStage,
} from './coordinator';
export type {
  ExecutionDecision,
  ApprovalStage,
  ApprovalChain,
} from './coordinator';

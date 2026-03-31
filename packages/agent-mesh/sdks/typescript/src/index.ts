// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { AgentIdentity, IdentityRegistry, stripKeyPrefix, safeBase64Decode } from './identity';
export { TrustManager } from './trust';
export { PolicyEngine, PolicyConflictResolver } from './policy';
export type { PolicyDecision } from './policy';
export { AuditLogger } from './audit';
export { AgentMeshClient } from './client';
export { GovernanceMetrics } from './metrics';

export {
  ConflictResolutionStrategy,
  PolicyScope,
} from './types';

export type {
  AgentIdentityJSON,
  IdentityStatus,
  TrustConfig,
  TrustScore,
  TrustTier,
  TrustVerificationResult,
  PolicyRule,
  Policy,
  PolicyAction,
  LegacyPolicyDecision,
  PolicyDecisionResult,
  CandidateDecision,
  ResolutionResult,
  AuditConfig,
  AuditEntry,
  AgentMeshConfig,
  GovernanceResult,
} from './types';

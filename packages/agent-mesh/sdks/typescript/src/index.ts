// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { AgentIdentity } from './identity';
export { TrustManager } from './trust';
export { PolicyEngine } from './policy';
export type { PolicyDecision } from './policy';
export { AuditLogger } from './audit';
export { AgentMeshClient } from './client';

export type {
  AgentIdentityJSON,
  TrustConfig,
  TrustScore,
  TrustTier,
  TrustVerificationResult,
  PolicyRule,
  AuditConfig,
  AuditEntry,
  AgentMeshConfig,
  GovernanceResult,
} from './types';

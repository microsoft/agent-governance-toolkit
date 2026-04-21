// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { AgentIdentity, IdentityRegistry, stripKeyPrefix, safeBase64Decode } from './identity';
export { TrustManager } from './trust';
export { PolicyEngine, PolicyConflictResolver } from './policy';
export type { PolicyDecision } from './policy';
export { AuditLogger } from './audit';
export { AgentMeshClient } from './client';
export { GovernanceMetrics } from './metrics';
export { McpSecurityScanner, McpThreatType } from './mcp';
export type { McpScanResult, McpThreat, McpToolDefinition } from './mcp';
export { LifecycleManager, LifecycleState } from './lifecycle';
export type { LifecycleEvent } from './lifecycle';

// E2E Encryption (AgentMesh Wire Protocol v1.0)
export {
  X3DHKeyManager, generateX25519KeyPair, ed25519ToX25519,
  DoubleRatchet,
  SecureChannel,
} from './encryption';
export type {
  X25519KeyPair, PreKeyBundle, X3DHResult,
  MessageHeader, EncryptedMessage, RatchetState,
  ChannelEstablishment,
} from './encryption';

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

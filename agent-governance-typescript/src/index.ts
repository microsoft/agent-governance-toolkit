// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export { AgentIdentity, IdentityRegistry, stripKeyPrefix, safeBase64Decode } from './identity';
export { TrustManager } from './trust';
export { PolicyEngine, PolicyConflictResolver } from './policy';
export type { PolicyDecision } from './policy';
export { AuditLogger } from './audit';
export { AgentMeshClient } from './client';
export { GenericFrameworkAdapter, FrameworkInvocationHandle } from './framework-adapter';
export { KillSwitch } from './kill-switch';
export {
  CircuitBreaker,
  ErrorBudgetTracker,
  GovernanceMetrics,
  SLOTracker,
  TraceCapture,
} from './metrics';
export { McpSecurityScanner, McpThreatType } from './mcp';
export type { McpScanResult, McpThreat, McpToolDefinition } from './mcp';
export { LifecycleManager, LifecycleState } from './lifecycle';
export type { LifecycleEvent } from './lifecycle';
export { ShadowDiscovery } from './discovery';
export { CedarBackend } from './policy-backends/cedar';
export { OPABackend } from './policy-backends/opa';
export { PromptDefenseEvaluator } from './prompt-defense';
export { RingEnforcer, RingBreachError } from './rings';
export { GovernanceVerifier } from './verify';
export { SurfaceParityChecker } from './surface-parity';
export { CascadeContainmentManager } from './cascade-containment';
export { ContextPoisoningDetector } from './context-poisoning';
export { OciManifestAdapter } from './oci-manifest';
export {
  SessionStatus,
  ExecutionStatus,
  defaultSandboxConfig,
  DockerSandboxProvider,
} from './sandbox';
export type {
  SandboxConfig,
  SandboxResult,
  SessionHandle,
  ExecutionHandle,
  SandboxProvider,
} from './sandbox';

// E2E Encryption (AgentMesh Wire Protocol v1.0)
export {
  X3DHKeyManager, generateX25519KeyPair, ed25519ToX25519,
  DoubleRatchet,
  SecureChannel,
  MeshClient,
} from './encryption';
export type {
  X25519KeyPair, PreKeyBundle, X3DHResult,
  MessageHeader, EncryptedMessage, RatchetState,
  ChannelEstablishment,
  MeshClientOptions, MeshSession, WebSocketFactory,
} from './encryption';

export {
  ConflictResolutionStrategy,
  ExecutionRing,
  PolicyScope,
} from './types';

export type {
  AgentIdentityJSON,
  BackendDecision,
  BackendEvaluationOutcome,
  IdentityStatus,
  TrustConfig,
  TrustScore,
  TrustTier,
  TrustVerificationResult,
  PolicyRule,
  PolicyBackendEvaluationResult,
  Policy,
  PolicyAction,
  LegacyPolicyDecision,
  PolicyDecisionResult,
  CandidateDecision,
  ExecutionControlConfig,
  ExternalPolicyBackend,
  ResolutionResult,
  KillSwitchConfig,
  KillSwitchResult,
  AuditConfig,
  AuditEntry,
  AgentMeshConfig,
  GovernanceResult,
  RingViolation,
  GovernanceSurface,
  SurfaceRuleMapping,
  SurfaceGap,
  SurfaceParityReport,
  AgentHealthStatus,
  AgentNode,
  BlastRadiusPolicy,
  CascadeAction,
  CascadeAnalysis,
  CascadeContainmentConfig,
  CascadeEvent,
  ContextPoisoningConfig,
  PoisoningPattern,
  ContextEntry,
  PoisoningFinding,
  ContextPoisoningScanResult,
  ContextIsolationViolation,
  OciManifest,
  OciDescriptor,
  AICard,
  AICardSkill,
  AICardCapabilities,
  AICardInvocation,
  OciPackageResult,
} from './types';
export type { PromptDefenseConfig, PromptDefenseFinding, PromptDefenseReport } from './prompt-defense';
export type {
  ControlResult,
  FileIntegrityResult,
  GovernanceAttestation,
  GovernanceVerificationOptions,
  IntegrityManifest,
  IntegrityManifestFile,
  RuntimeEvidence,
  RuntimeEvidenceCheck,
  RuntimeEvidenceDeployment,
  VerifierControlSpec,
} from './verify';
export type {
  FrameworkAdapterResult,
  FrameworkInvocation,
  FrameworkInvocationOutcome,
  GenericFrameworkAdapterOptions,
} from './framework-adapter';
export type {
  CircuitBreakerState,
  ErrorBudgetSnapshot,
  ExecutionTrace,
  GovernanceMetricsConfig,
  GovernanceMetricsSnapshot,
  MetricEvent,
  MetricSink,
  SLOStatus,
  TraceSpan,
  TraceSpanKind,
  TraceSpanStatus,
} from './metrics';
export type {
  DetectionBasis,
  DiscoveryEvidence,
  DiscoveryRiskAssessment,
  DiscoveryRiskLevel,
  DiscoveryScanResult,
  DiscoveryStatus,
  DiscoveredAgent,
  RegisteredAgentRecord,
  ShadowAgentRecord,
  ShadowDiscoveryOptions,
} from './discovery';

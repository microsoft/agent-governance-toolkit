// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ΓöÇΓöÇ Identity ΓöÇΓöÇ

/** Lifecycle status for agent identities. */
export type IdentityStatus = 'active' | 'suspended' | 'revoked';

export interface AgentIdentityJSON {
  did: string;
  publicKey: string; // base64
  privateKey?: string; // base64, optional for export
  capabilities: string[];
  name?: string;
  description?: string;
  sponsor?: string;
  organization?: string;
  status?: IdentityStatus;
  parentDid?: string;
  delegationDepth?: number;
  createdAt?: string;
  expiresAt?: string;
}

// ΓöÇΓöÇ Trust ΓöÇΓöÇ

export interface TrustConfig {
  /** Initial trust score for unknown agents (default 0.5) */
  initialScore?: number;
  /** Decay factor applied over time (default 0.95) */
  decayFactor?: number;
  /** Tier thresholds */
  thresholds?: {
    untrusted: number;
    provisional: number;
    trusted: number;
    verified: number;
  };
  /** Optional file path for persisting trust scores across restarts */
  persistPath?: string;
}

export type TrustTier = 'Untrusted' | 'Provisional' | 'Trusted' | 'Verified';

export interface TrustScore {
  overall: number;
  dimensions: Record<string, number>;
  tier: TrustTier;
}

export interface TrustVerificationResult {
  verified: boolean;
  trustScore: TrustScore;
  reason?: string;
}

// ΓöÇΓöÇ Policy ΓöÇΓöÇ

/** Actions a policy rule can take. */
export type PolicyAction = 'allow' | 'deny' | 'warn' | 'require_approval' | 'log';

/** Legacy decision type kept for backward compatibility with AuditLogger/Client. */
export type LegacyPolicyDecision = 'allow' | 'deny' | 'review';

/** Conflict resolution strategies. */
export enum ConflictResolutionStrategy {
  DenyOverrides = 'deny_overrides',
  AllowOverrides = 'allow_overrides',
  PriorityFirstMatch = 'priority_first_match',
  MostSpecificWins = 'most_specific_wins',
}

/** Policy scope for conflict resolution specificity. */
export enum PolicyScope {
  Global = 'global',
  Tenant = 'tenant',
  Agent = 'agent',
}

/** A rich policy rule matching the Python/NET SDK. */
export interface PolicyRule {
  /** Rule name (required for rich policies). */
  name?: string;
  description?: string;

  /** Condition expression (string) or legacy flat conditions. */
  condition?: string | Record<string, unknown>;

  /** @deprecated Use `condition` instead. Kept for backward compatibility. */
  conditions?: Record<string, unknown>;

  /** Legacy: action pattern for flat rule matching. */
  action?: string;

  /** Effect for legacy flat rules. */
  effect?: LegacyPolicyDecision;

  /** Rich rule action. */
  ruleAction?: PolicyAction;

  /** Rate limit (e.g., '100/hour'). */
  limit?: string;

  /** Required approvers for require_approval action. */
  approvers?: string[];

  /** Priority (higher = evaluated first). */
  priority?: number;

  /** Whether this rule is enabled (default true). */
  enabled?: boolean;

  /** Governance surfaces this rule applies to (omit for universal rules). */
  surfaces?: GovernanceSurface[];
}

/** Governance surface where policy enforcement occurs. */
export type GovernanceSurface = 'cli' | 'ide' | 'api' | 'unknown';

/** Maps a rule to the surfaces it covers. */
export interface SurfaceRuleMapping {
  rule: PolicyRule;
  policyName: string;
  detectedSurfaces: GovernanceSurface[];
  isUniversal: boolean;
}

/** A gap where a rule exists for one surface but not another. */
export interface SurfaceGap {
  ruleName: string;
  policyName: string;
  presentOn: GovernanceSurface[];
  missingFrom: GovernanceSurface[];
  ruleAction: PolicyAction | undefined;
  severity: 'high' | 'medium' | 'low';
  recommendation: string;
}

/** Report of governance parity analysis across surfaces. */
export interface SurfaceParityReport {
  analyzedAt: Date;
  totalRules: number;
  universalRules: number;
  surfaceSpecificRules: number;
  gaps: SurfaceGap[];
  mappings: SurfaceRuleMapping[];
  surfaceCoverage: Record<GovernanceSurface, number>;
  parityScore: number;
}

/** A complete policy document (matches Python Policy model). */
export interface Policy {
  apiVersion?: string;
  version?: string;
  name: string;
  description?: string;
  agent?: string;
  agents?: string[];
  scope?: string;
  rules: PolicyRule[];
  default_action?: 'allow' | 'deny';
}

/** Rich policy decision result. */
export interface PolicyDecisionResult {
  allowed: boolean;
  action: PolicyAction;
  matchedRule?: string;
  policyName?: string;
  reason?: string;
  approvers: string[];
  rateLimited: boolean;
  evaluatedAt: Date;
  evaluationMs?: number;
}

/** Candidate decision for conflict resolution. */
export interface CandidateDecision {
  action: PolicyAction;
  priority: number;
  scope: PolicyScope;
  policyName: string;
  ruleName: string;
  reason: string;
  approvers: string[];
}

/** Result of conflict resolution. */
export interface ResolutionResult {
  winningDecision: CandidateDecision;
  strategyUsed: ConflictResolutionStrategy;
  candidatesEvaluated: number;
  conflictDetected: boolean;
  resolutionTrace: string[];
}

export type BackendDecision = 'allow' | 'deny' | 'review';

export interface BackendEvaluationOutcome {
  backend: string;
  decision: BackendDecision;
  reason?: string;
  error?: string;
}

export interface ExternalPolicyBackend {
  name: string;
  evaluateAction?(
    action: string,
    context: Record<string, unknown>,
  ): Promise<BackendDecision | BackendEvaluationOutcome> | BackendDecision | BackendEvaluationOutcome;
  evaluatePolicy?(
    agentDid: string,
    context: Record<string, unknown>,
  ): Promise<BackendDecision | BackendEvaluationOutcome | PolicyDecisionResult>
    | BackendDecision
    | BackendEvaluationOutcome
    | PolicyDecisionResult;
}

export interface PolicyBackendEvaluationResult {
  localDecision: LegacyPolicyDecision | PolicyDecisionResult;
  backendResults: BackendEvaluationOutcome[];
  effectiveDecision: LegacyPolicyDecision;
  effectivePolicyResult?: PolicyDecisionResult;
  deniedBy: string[];
}

// Execution controls

export enum ExecutionRing {
  Ring0 = 0,
  Ring1 = 1,
  Ring2 = 2,
  Ring3 = 3,
}

export interface ExecutionControlConfig {
  agentRing?: ExecutionRing;
  defaultRing?: ExecutionRing;
  actionRings?: Record<string, ExecutionRing>;
  quarantineOnBreach?: boolean;
  killOnBreach?: boolean;
}

export interface RingViolation {
  action: string;
  agentRing: ExecutionRing;
  requiredRing: ExecutionRing;
  message: string;
}

export interface KillSwitchConfig {
  enabled?: boolean;
  defaultSubstituteAgentId?: string;
}

export interface KillSwitchResult {
  agentId: string;
  action?: string;
  reason: string;
  killedAt: string;
  callbacksExecuted: number;
  compensationsExecuted: number;
  handoffAgentId?: string;
}

// ΓöÇΓöÇ Cascade Containment ΓöÇΓöÇ

/** Configuration for blast radius containment, keyed by trust tier. */
export interface BlastRadiusPolicy {
  maxDependencyDepth: number;
  maxFanout: number;
  circuitBreakerThreshold: number;
  circuitBreakerResetMs: number;
  autoQuarantine: boolean;
  autoRollback: boolean;
}

/** Agent node in the dependency graph. */
export interface AgentNode {
  agentId: string;
  trustTier: TrustTier;
  healthStatus: AgentHealthStatus;
  dependencies: string[];
  dependents: string[];
  lastHealthCheck?: string;
}

export type AgentHealthStatus = 'healthy' | 'degraded' | 'failing' | 'unreachable';

/** Event emitted when a cascade containment action is taken. */
export interface CascadeEvent {
  eventId: string;
  timestamp: string;
  sourceAgentId: string;
  affectedAgentIds: string[];
  action: CascadeAction;
  reason: string;
  blastRadius: number;
  containedAt: number;
}

export type CascadeAction =
  | 'circuit_opened'
  | 'agent_degraded'
  | 'agent_quarantined'
  | 'agent_killed'
  | 'rollback_triggered'
  | 'health_propagated';

/** Configuration for cascade containment. */
export interface CascadeContainmentConfig {
  defaultPolicy: BlastRadiusPolicy;
  tierPolicies?: Partial<Record<TrustTier, Partial<BlastRadiusPolicy>>>;
  cascadeThreshold?: number;
}

/** Summary of cascade containment analysis. */
export interface CascadeAnalysis {
  totalAgents: number;
  healthyAgents: number;
  degradedAgents: number;
  failingAgents: number;
  openCircuitBreakers: number;
  cascadeRisk: 'low' | 'medium' | 'high' | 'critical';
  blastRadiusMap: Record<string, number>;
  events: CascadeEvent[];
}

// ΓöÇΓöÇ Context Poisoning Detection ΓöÇΓöÇ

/** Configuration for context poisoning detection. */
export interface ContextPoisoningConfig {
  maxContextSizeBytes?: number;
  maxEntriesPerSession?: number;
  entropyThreshold?: number;
  similarityThreshold?: number;
  enableIsolation?: boolean;
  knownPatterns?: PoisoningPattern[];
}

/** A known poisoning attack pattern. */
export interface PoisoningPattern {
  id: string;
  name: string;
  description: string;
  detector: 'regex' | 'entropy' | 'repetition' | 'injection' | 'size';
  pattern?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/** A context entry stored in agent memory. */
export interface ContextEntry {
  entryId: string;
  sessionId: string;
  agentId: string;
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

/** Finding from context poisoning analysis. */
export interface PoisoningFinding {
  findingId: string;
  patternId: string;
  patternName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  entryId: string;
  sessionId: string;
  agentId: string;
  description: string;
  evidence: string;
  recommendation: string;
}

/** Result of context poisoning scan. */
export interface ContextPoisoningScanResult {
  scannedAt: string;
  entriesScanned: number;
  findings: PoisoningFinding[];
  integrityValid: boolean;
  isolationViolations: ContextIsolationViolation[];
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

/** Violation of memory isolation between sessions. */
export interface ContextIsolationViolation {
  sourceSessionId: string;
  targetSessionId: string;
  agentId: string;
  sharedEntryIds: string[];
  description: string;
}

// ΓöÇΓöÇ OCI Manifest Adapter ΓöÇΓöÇ

/** OCI manifest format (v2 schema). */
export interface OciManifest {
  schemaVersion: 2;
  mediaType: string;
  config: OciDescriptor;
  layers: OciDescriptor[];
  annotations?: Record<string, string>;
}

/** OCI content descriptor. */
export interface OciDescriptor {
  mediaType: string;
  digest: string;
  size: number;
  annotations?: Record<string, string>;
}

/** AI Card agent metadata (framework-neutral). */
export interface AICard {
  name: string;
  version: string;
  description?: string;
  author?: string;
  license?: string;
  homepage?: string;
  repository?: string;
  skills?: AICardSkill[];
  capabilities?: AICardCapabilities;
  invocation?: AICardInvocation;
  metadata?: Record<string, unknown>;
}

export interface AICardSkill {
  name: string;
  description?: string;
  parameters?: Record<string, string>;
  returns?: string;
}

export interface AICardCapabilities {
  languages?: string[];
  domains?: string[];
  input_modes?: string[];
  output_modes?: string[];
  streaming?: boolean;
  async?: boolean;
}

export interface AICardInvocation {
  protocol?: string;
  endpoint?: string;
  authentication?: { type: string; required: boolean };
  method?: string;
  format?: string;
}

/** Result of converting AGT identity to OCI manifest. */
export interface OciPackageResult {
  manifest: OciManifest;
  aiCard: AICard;
  configBlob: string;
  layers: Array<{ descriptor: OciDescriptor; content: string }>;
}

// ΓöÇΓöÇ Audit ΓöÇΓöÇ

export interface AuditConfig {
  /** Maximum entries kept in memory (default 10000) */
  maxEntries?: number;
}

export interface AuditEntry {
  timestamp: string;
  agentId: string;
  action: string;
  decision: LegacyPolicyDecision;
  hash: string;
  previousHash: string;
}

// ΓöÇΓöÇ Client ΓöÇΓöÇ

export interface AgentMeshConfig {
  agentId: string;
  capabilities?: string[];
  trust?: TrustConfig;
  policyRules?: PolicyRule[];
  audit?: AuditConfig;
  execution?: ExecutionControlConfig;
  killSwitch?: KillSwitchConfig;
}

export interface GovernanceResult {
  decision: LegacyPolicyDecision;
  trustScore: TrustScore;
  auditEntry: AuditEntry;
  executionTime: number;
  ringViolation?: RingViolation;
  killSwitchResult?: KillSwitchResult;
  lifecycleState?: string;
  lifecycleReason?: string;
}

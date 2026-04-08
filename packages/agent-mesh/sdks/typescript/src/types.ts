// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── Identity ──

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

// ── Trust ──

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

// ── Policy ──

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

// ── Audit ──

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

// ── Client ──

export interface AgentMeshConfig {
  agentId: string;
  capabilities?: string[];
  trust?: TrustConfig;
  policyRules?: PolicyRule[];
  audit?: AuditConfig;
}

export interface GovernanceResult {
  decision: LegacyPolicyDecision;
  trustScore: TrustScore;
  auditEntry: AuditEntry;
  executionTime: number;
}

// ── MCP Security ──

export type MCPMaybePromise<T> = T | Promise<T>;

export type MCPFindingSeverity = 'info' | 'warning' | 'critical';

export type MCPResponseThreatType =
  | 'instruction_injection'
  | 'imperative_language'
  | 'credential_leak'
  | 'exfiltration_url';

export interface MCPResponseFinding {
  type: MCPResponseThreatType;
  severity: MCPFindingSeverity;
  message: string;
  matchedText?: string;
  path?: string;
}

export interface MCPResponseScannerConfig {
  blockSeverities?: MCPFindingSeverity[];
  sanitizeText?: boolean;
  suspiciousHosts?: string[];
  clock?: MCPClock;
  scanTimeoutMs?: number;
  logger?: MCPDebugLogger;
}

export interface MCPResponseScanResult<T = unknown> {
  safe: boolean;
  blocked: boolean;
  findings: MCPResponseFinding[];
  original: T;
  sanitized: T;
}

export interface CredentialPatternDefinition {
  name: string;
  pattern: RegExp | string;
  replacement?: string;
}

export interface MCPRedaction {
  type: string;
  path?: string;
  replacement: string;
  matchedText?: string;
}

export interface CredentialRedactorConfig {
  replacementText?: string;
  redactSensitiveKeys?: boolean;
  customPatterns?: CredentialPatternDefinition[];
  logger?: MCPDebugLogger;
}

export interface CredentialRedactionResult<T = unknown> {
  redacted: T;
  redactions: MCPRedaction[];
}

export interface MCPClock {
  now(): number | Date;
  monotonic?(): number;
}

export interface MCPDebugLogger {
  debug?(message: string, details?: Record<string, unknown>): void;
}

export interface MCPSessionTokenPayload {
  tokenVersion: string;
  agentId: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
  metadata?: Record<string, string>;
}

export interface MCPSessionRecord {
  agentId: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
  tokenId: string;
  metadata?: Record<string, string>;
}

export interface MCPSessionStore {
  listSessions(agentId: string): MCPMaybePromise<MCPSessionRecord[]>;
  getSession(
    agentId: string,
    sessionId: string,
  ): MCPMaybePromise<MCPSessionRecord | undefined>;
  upsertSession(record: MCPSessionRecord): MCPMaybePromise<void>;
  removeSession(agentId: string, sessionId: string): MCPMaybePromise<void>;
}

export interface MCPSessionAuthConfig {
  secret: string | Uint8Array;
  ttlMs?: number;
  maxConcurrentSessions?: number;
  maxClockSkewMs?: number;
  clock?: MCPClock;
  sessionStore?: MCPSessionStore;
  logger?: MCPDebugLogger;
}

export interface MCPSessionIssueResult {
  token: string;
  payload: MCPSessionTokenPayload;
}

export interface MCPSessionVerificationResult {
  valid: boolean;
  reason?: string;
  payload?: MCPSessionTokenPayload;
}

export interface MCPNonceStore {
  consume(
    scope: string,
    nonce: string,
    expiresAt: number,
  ): MCPMaybePromise<boolean>;
  reset?(scope?: string): MCPMaybePromise<void>;
}

export interface MCPMessageEnvelope<T = unknown> {
  payload: T;
  timestamp: number;
  nonce: string;
  signature: string;
  keyId?: string;
}

export interface MCPMessageSignerConfig {
  secret: string | Uint8Array;
  keyId?: string;
  maxClockSkewMs?: number;
  nonceTtlMs?: number;
  clock?: MCPClock;
  nonceStore?: MCPNonceStore;
  logger?: MCPDebugLogger;
}

export interface MCPMessageVerificationResult<T = unknown> {
  valid: boolean;
  reason?: string;
  envelope?: MCPMessageEnvelope<T>;
}

export interface MCPSlidingRateLimitConfig {
  maxRequests: number;
  windowMs: number;
  clock?: MCPClock;
  logger?: MCPDebugLogger;
}

export interface MCPSlidingRateLimitResult {
  allowed: boolean;
  count: number;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterMs: number;
}

export enum MCPThreatType {
  ToolPoisoning = 'tool_poisoning',
  RugPull = 'rug_pull',
  CrossServerAttack = 'cross_server_attack',
  ConfusedDeputy = 'confused_deputy',
  HiddenInstruction = 'hidden_instruction',
  DescriptionInjection = 'description_injection',
}

export enum MCPSeverity {
  Info = 'info',
  Warning = 'warning',
  Critical = 'critical',
}

export interface MCPThreat {
  threatType: MCPThreatType;
  severity: MCPSeverity;
  toolName: string;
  serverName: string;
  message: string;
  matchedPattern?: string;
  details?: Record<string, unknown>;
}

export interface ToolFingerprint {
  toolName: string;
  serverName: string;
  descriptionHash: string;
  schemaHash: string;
  firstSeen: number;
  lastSeen: number;
  version: number;
}

export interface MCPToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface MCPScanResult {
  safe: boolean;
  threats: MCPThreat[];
  toolsScanned: number;
  toolsFlagged: number;
}

export interface MCPScanAuditRecord {
  timestamp: string;
  action: string;
  toolName: string;
  serverName: string;
  threatsFound: number;
  threatTypes: MCPThreatType[];
}

export enum ApprovalStatus {
  Pending = 'pending',
  Approved = 'approved',
  Denied = 'denied',
}

export interface MCPApprovalRequest {
  agentId: string;
  toolName: string;
  params: Record<string, unknown>;
  auditParams: Record<string, unknown>;
  findings: MCPResponseFinding[];
  policyDecision?: LegacyPolicyDecision;
}

export type MCPApprovalHandler = (
  request: MCPApprovalRequest,
) => MCPMaybePromise<ApprovalStatus>;

export interface MCPMetricAttributes {
  [key: string]: string | number | boolean;
}

export interface MCPMetricRecorder {
  recordMcpDecision(decision: string, attributes?: MCPMetricAttributes): void;
  recordMcpThreatsDetected(
    count: number,
    attributes?: MCPMetricAttributes,
  ): void;
  recordMcpRateLimitHit(
    agentId: string,
    attributes?: MCPMetricAttributes,
  ): void;
  recordMcpScan(scanned: number, flagged: number, attributes?: MCPMetricAttributes): void;
}

export interface MCPAuditSink {
  record(entry: MCPGatewayAuditEntry): MCPMaybePromise<void>;
}

export interface MCPGatewayConfig {
  deniedTools?: string[];
  allowedTools?: string[];
  sensitiveTools?: string[];
  blockedPatterns?: Array<string | RegExp>;
  enableBuiltinSanitization?: boolean;
  clock?: MCPClock;
  scanTimeoutMs?: number;
  logger?: MCPDebugLogger;
  policyEvaluator?: {
    evaluate(action: string, context?: Record<string, unknown>): LegacyPolicyDecision;
  };
  approvalHandler?: MCPApprovalHandler;
  rateLimiter?: {
    consume(agentId: string): MCPMaybePromise<MCPSlidingRateLimitResult>;
  };
  rateLimit?: {
    maxRequests: number;
    windowMs: number;
  };
  auditSink?: MCPAuditSink;
  metrics?: MCPMetricRecorder;
}

export interface MCPGatewayDecisionResult {
  allowed: boolean;
  reason: string;
  auditParams: Record<string, unknown>;
  findings: MCPResponseFinding[];
  approvalStatus?: ApprovalStatus;
  policyDecision?: LegacyPolicyDecision;
  rateLimit?: MCPSlidingRateLimitResult;
}

export interface MCPSecurityScannerConfig {
  clock?: MCPClock;
  scanTimeoutMs?: number;
  logger?: MCPDebugLogger;
}

export interface MCPGatewayAuditEntry {
  timestamp: string;
  agentId: string;
  toolName: string;
  params: Record<string, unknown>;
  auditParams: Record<string, unknown>;
  allowed: boolean;
  reason: string;
  approvalStatus?: ApprovalStatus;
  policyDecision?: LegacyPolicyDecision;
  findings: MCPResponseFinding[];
}

export interface MCPWrappedServerConfig {
  serverConfig: Record<string, unknown>;
  allowedTools: string[];
  deniedTools: string[];
  sensitiveTools: string[];
  rateLimit?: {
    maxRequests: number;
    windowMs: number;
  };
}

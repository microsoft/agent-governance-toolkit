// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export interface Clock {
  now(): Date;
  monotonic(): number;
}

export interface NonceGenerator {
  generate(): string;
}

export interface McpSession {
  id: string;
  agentId: string;
  tokenId: string;
  issuedAt: Date;
  expiresAt: Date;
  metadata?: Record<string, string>;
}

export interface McpSessionStore {
  get(id: string): Promise<McpSession | null>;
  set(session: McpSession): Promise<void>;
  delete(id: string): Promise<void>;
  listByAgent(agentId: string): Promise<McpSession[]>;
}

export interface McpNonceStore {
  has(nonce: string): Promise<boolean>;
  add(nonce: string, expiresAt: Date): Promise<void>;
  cleanup(): Promise<void>;
}

export interface AgentBucket {
  agentId: string;
  hits: Date[];
  lastSeenAt?: Date;
}

export interface McpRateLimitStore {
  getBucket(agentId: string): Promise<AgentBucket | null>;
  setBucket(agentId: string, bucket: AgentBucket): Promise<void>;
  deleteBucket?(agentId: string): Promise<void>;
  cleanupInactive?(inactiveBefore: Date, maxEntries?: number): Promise<void>;
}

export interface McpAuditEntry {
  timestamp: string;
  stage: string;
  agentId?: string;
  toolName?: string;
  decision?: 'allow' | 'deny';
  reason?: string;
  approvalStatus?: ApprovalStatus;
  params?: Record<string, unknown>;
  findings?: McpResponseFinding[];
  details?: Record<string, unknown>;
}

export interface McpAuditSink {
  record(entry: McpAuditEntry): Promise<void>;
}

export interface McpMetricLabels {
  toolName?: string;
  decision?: string;
  stage?: string;
}

export interface McpMetrics {
  recordDecision(labels: McpMetricLabels): void;
  recordThreats(count: number, labels: McpMetricLabels): void;
  recordRateLimitHit(labels: McpMetricLabels): void;
  recordScan(labels: McpMetricLabels): void;
}

export type FindingSeverity = 'info' | 'warning' | 'critical';

export type McpResponseThreatType =
  | 'instruction_injection'
  | 'imperative_language'
  | 'credential_leak'
  | 'exfiltration_url';

export interface McpResponseFinding {
  type: McpResponseThreatType;
  severity: FindingSeverity;
  message: string;
  matchedText?: string;
  path?: string;
}

export interface CredentialPatternDefinition {
  name: string;
  pattern: RegExp | string;
  replacement?: string;
}

export interface CredentialRedaction {
  type: string;
  path?: string;
  replacement: string;
  matchedValueType?: string;
  matchedTextPreview?: string;
}

export interface CredentialRedactorConfig {
  replacementText?: string;
  redactSensitiveKeys?: boolean;
  customPatterns?: CredentialPatternDefinition[];
  clock?: Clock;
  scanTimeoutMs?: number;
  logger?: McpDebugLogger;
}

export interface CredentialRedactionResult<T = unknown> {
  redacted: T;
  redactions: CredentialRedaction[];
}

export interface McpResponseScannerConfig {
  blockSeverities?: FindingSeverity[];
  sanitizeText?: boolean;
  clock?: Clock;
  scanTimeoutMs?: number;
  logger?: McpDebugLogger;
}

export interface McpDebugLogger {
  debug?(message: string, details?: Record<string, unknown>): void;
}

export interface McpResponseScanResult<T = unknown> {
  safe: boolean;
  blocked: boolean;
  findings: McpResponseFinding[];
  original: T;
  sanitized: T;
}

export interface McpSessionAuthConfig {
  secret: string | Uint8Array;
  sessionStore?: McpSessionStore;
  clock?: Clock;
  nonceGenerator?: NonceGenerator;
  ttlMs?: number;
  maxClockSkewMs?: number;
  maxConcurrentSessions?: number;
  logger?: McpDebugLogger;
}

export interface McpSessionTokenPayload {
  version: 'v1';
  sessionId: string;
  agentId: string;
  tokenId: string;
  issuedAt: string;
  expiresAt: string;
  metadata?: Record<string, string>;
}

export interface McpSessionIssueResult {
  token: string;
  payload: McpSessionTokenPayload;
}

export interface McpSessionVerificationResult {
  valid: boolean;
  reason?: string;
  payload?: McpSessionTokenPayload;
}

export interface McpMessageSignerConfig {
  secret: string | Uint8Array;
  nonceStore?: McpNonceStore;
  clock?: Clock;
  nonceGenerator?: NonceGenerator;
  maxClockSkewMs?: number;
  nonceTtlMs?: number;
  maxNonceEntries?: number;
  logger?: McpDebugLogger;
}

export interface McpMessageEnvelope<T = unknown> {
  payload: T;
  timestamp: string;
  nonce: string;
  signature: string;
  keyId?: string;
}

export interface McpMessageVerificationResult<T = unknown> {
  valid: boolean;
  reason?: string;
  envelope?: McpMessageEnvelope<T>;
}

export interface McpSlidingRateLimiterConfig {
  maxRequests: number;
  windowMs: number;
  store?: McpRateLimitStore;
  clock?: Clock;
  inactiveEntryTtlMs?: number;
  maxTrackedAgents?: number;
  logger?: McpDebugLogger;
}

export interface McpSlidingRateLimitResult {
  allowed: boolean;
  count: number;
  limit: number;
  remaining: number;
  resetAt: Date;
  retryAfterMs: number;
}

export enum McpThreatType {
  ToolPoisoning = 'tool_poisoning',
  RugPull = 'rug_pull',
  CrossServerAttack = 'cross_server_attack',
  HiddenInstruction = 'hidden_instruction',
  DescriptionInjection = 'description_injection',
}

export enum McpSeverity {
  Info = 'info',
  Warning = 'warning',
  Critical = 'critical',
}

export interface McpThreat {
  threatType: McpThreatType;
  severity: McpSeverity;
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
  firstSeen: Date;
  lastSeen: Date;
  version: number;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpScanResult {
  safe: boolean;
  threats: McpThreat[];
  toolsScanned: number;
  toolsFlagged: number;
}

export interface McpSecurityScannerConfig {
  clock?: Clock;
  scanTimeoutMs?: number;
  logger?: McpDebugLogger;
}

export enum ApprovalStatus {
  Pending = 'pending',
  Approved = 'approved',
  Denied = 'denied',
}

export interface McpApprovalRequest {
  agentId: string;
  toolName: string;
  params: Record<string, unknown>;
  redactedParams: Record<string, unknown>;
  findings: McpResponseFinding[];
  stage: string;
}

export type McpApprovalHandler = (
  request: McpApprovalRequest,
) => Promise<ApprovalStatus> | ApprovalStatus;

export interface McpGatewayPolicyEvaluator {
  evaluate(
    toolName: string,
    context: Record<string, unknown>,
  ): Promise<'allow' | 'deny' | 'review'> | 'allow' | 'deny' | 'review';
}

export interface McpGatewayConfig {
  deniedTools?: string[];
  allowedTools?: string[];
  sensitiveTools?: string[];
  blockedPatterns?: Array<string | RegExp>;
  rateLimit?: McpSlidingRateLimiterConfig;
  approvalHandler?: McpApprovalHandler;
  policyEvaluator?: McpGatewayPolicyEvaluator;
  rateLimiter?: {
    consume(agentId: string): Promise<McpSlidingRateLimitResult> | McpSlidingRateLimitResult;
  };
  auditSink?: McpAuditSink;
  metrics?: McpMetrics;
  clock?: Clock;
  scanTimeoutMs?: number;
  logger?: McpDebugLogger;
}

export interface McpGatewayDecision {
  allowed: boolean;
  reason: string;
  redactedParams: Record<string, unknown>;
  findings: McpResponseFinding[];
  approvalStatus?: ApprovalStatus;
  rateLimit?: McpSlidingRateLimitResult;
}

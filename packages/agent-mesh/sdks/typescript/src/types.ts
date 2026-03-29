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

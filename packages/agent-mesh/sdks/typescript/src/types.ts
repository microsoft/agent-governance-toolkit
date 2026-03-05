// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { PolicyDecision } from './policy';

// ── Identity ──

export interface AgentIdentityJSON {
  did: string;
  publicKey: string; // base64
  privateKey?: string; // base64, optional for export
  capabilities: string[];
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

export type { PolicyDecision } from './policy';

export interface PolicyRule {
  action: string;
  effect: PolicyDecision;
  conditions?: Record<string, unknown>;
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
  decision: PolicyDecision;
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
  decision: PolicyDecision;
  trustScore: TrustScore;
  auditEntry: AuditEntry;
  executionTime: number;
}

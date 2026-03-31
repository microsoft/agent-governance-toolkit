// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Shared types for @agentmesh/mastra middleware.
 */

/** Policy definition for governance middleware. */
export interface GovernancePolicy {
  /** Maximum tool calls per minute per agent. */
  rateLimitPerMinute?: number;

  /** Blocked input patterns (regex strings). */
  blockedPatterns?: string[];

  /** PII fields to redact from inputs/outputs. */
  piiFields?: string[];

  /** Maximum input length in characters. */
  maxInputLength?: number;

  /** Allowed tool IDs (allowlist). Empty = all allowed. */
  allowedTools?: string[];

  /** Blocked tool IDs (denylist). */
  blockedTools?: string[];

  /** Custom policy check function. */
  customCheck?: (input: unknown, toolId: string) => Promise<GovernanceResult>;
}

/** Result of a governance policy check. */
export interface GovernanceResult {
  allowed: boolean;
  reason?: string;
  violations: string[];
  redactedInput?: unknown;
}

/** Configuration for trust gate. */
export interface TrustConfig {
  /** Minimum trust score to allow execution (0-1000). */
  minTrustScore: number;

  /** Trust score provider function. */
  getTrustScore: (agentId: string) => Promise<number>;

  /** Called when trust verification fails. */
  onTrustFailure?: (agentId: string, score: number) => Promise<void>;
}

/** Result of trust verification. */
export interface TrustVerification {
  verified: boolean;
  agentId: string;
  trustScore: number;
  threshold: number;
  timestamp: number;
}

/** Configuration for audit middleware. */
export interface AuditConfig {
  /** Whether to include input/output data in audit entries. */
  captureData?: boolean;

  /** Custom audit sink (default: console + in-memory). */
  sink?: (entry: AuditEntry) => Promise<void>;

  /** Maximum entries to keep in memory. */
  maxEntries?: number;
}

/** Single entry in the audit log. */
export interface AuditEntry {
  id: string;
  timestamp: number;
  toolId: string;
  agentId: string;
  action: "invoke" | "complete" | "deny" | "error";
  input?: unknown;
  output?: unknown;
  duration_ms?: number;
  governance?: GovernanceResult;
  trust?: TrustVerification;
  hash: string;
  previousHash: string;
}

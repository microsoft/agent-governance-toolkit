// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Governance metrics stubs for observability.
 * Replace with real OpenTelemetry instrumentation when configured.
 */
export class GovernanceMetrics {
  readonly enabled: boolean;

  constructor(enabled: boolean = false) {
    this.enabled = enabled;
  }

  /** Record a policy evaluation result. */
  recordPolicyDecision(decision: string, durationMs: number): void {
    // No-op stub
  }

  /** Record a trust score update. */
  recordTrustScore(agentId: string, score: number): void {
    // No-op stub
  }

  /** Record an audit chain append. */
  recordAuditEntry(seq: number): void {
    // No-op stub
  }
}

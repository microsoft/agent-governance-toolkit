// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Governance metrics stubs for observability.
 * Replace with real OpenTelemetry instrumentation when configured.
 */
export class GovernanceMetrics {
  readonly enabled: boolean;
  private readonly counters = new Map<string, number>();

  constructor(enabled: boolean = false) {
    this.enabled = enabled;
  }

  /** Record a policy evaluation result. */
  recordPolicyDecision(_decision: string, _durationMs: number): void {
    this.increment('policy_decisions');
  }

  /** Record a trust score update. */
  recordTrustScore(_agentId: string, _score: number): void {
    this.increment('trust_updates');
  }

  /** Record an audit chain append. */
  recordAuditEntry(_seq: number): void {
    this.increment('audit_entries');
  }

  /** Record an MCP governance decision. */
  recordMcpDecision(
    _decision: string,
    _attributes?: Record<string, string | number | boolean>,
  ): void {
    this.increment('mcp_decisions');
  }

  /** Record the number of MCP threats detected. */
  recordMcpThreatsDetected(
    count: number,
    _attributes?: Record<string, string | number | boolean>,
  ): void {
    this.increment('mcp_threats_detected', count);
  }

  /** Record an MCP rate-limit hit. */
  recordMcpRateLimitHit(
    _agentId: string,
    _attributes?: Record<string, string | number | boolean>,
  ): void {
    this.increment('mcp_rate_limit_hits');
  }

  /** Record MCP scan volume. */
  recordMcpScan(
    scanned: number,
    flagged: number,
    _attributes?: Record<string, string | number | boolean>,
  ): void {
    this.increment('mcp_scans', scanned);
    if (flagged > 0) {
      this.increment('mcp_threats_detected', flagged);
    }
  }

  getCounterValue(name: string): number {
    return this.counters.get(name) ?? 0;
  }

  private increment(name: string, delta: number = 1): void {
    if (!this.enabled) {
      return;
    }
    this.counters.set(name, (this.counters.get(name) ?? 0) + delta);
  }
}

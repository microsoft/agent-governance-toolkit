// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  CircuitBreaker,
  ErrorBudgetTracker,
  GovernanceMetrics,
  MetricEvent,
  MetricSink,
  SLOTracker,
  TraceCapture,
} from '../src/metrics';

class InMemorySink implements MetricSink {
  readonly events: MetricEvent[] = [];

  record(event: MetricEvent): void {
    this.events.push(event);
  }
}

describe('GovernanceMetrics', () => {
  it('defaults to disabled', () => {
    const metrics = new GovernanceMetrics();
    expect(metrics.enabled).toBe(false);
  });

  it('records metrics into snapshots and sinks when enabled', () => {
    const sink = new InMemorySink();
    const metrics = new GovernanceMetrics({ enabled: true, sinks: [sink] });

    metrics.recordPolicyDecision('allow', 12.5, { action: 'data.read' });
    metrics.recordTrustScore('agent-1', 0.82);
    metrics.recordAuditEntry(42);
    metrics.recordToolCall('search', 7.2);

    const snapshot = metrics.getSnapshot();
    expect(snapshot.counters['policy.decision.allow']).toBe(1);
    expect(snapshot.counters['audit.entries']).toBe(1);
    expect(snapshot.histograms['tool.duration_ms']).toEqual([7.2]);
    expect(snapshot.gauges['trust.score.agent-1']).toBe(0.82);
    expect(sink.events).toHaveLength(4);
  });
});

describe('ErrorBudgetTracker and SLOTracker', () => {
  it('calculates burn rate and exhaustion', () => {
    const budget = new ErrorBudgetTracker(0.99, 3600);
    for (let i = 0; i < 100; i += 1) {
      budget.recordEvent(i < 95);
    }

    const snapshot = budget.snapshot();
    expect(snapshot.errorEvents).toBe(5);
    expect(snapshot.burnRate).toBeGreaterThan(1);
    expect(snapshot.remainingPercent).toBeLessThanOrEqual(100);
  });

  it('evaluates healthy and critical SLO states', () => {
    const slo = new SLOTracker('governance-api', 0.99, 3600);
    for (let i = 0; i < 20; i += 1) {
      slo.recordEvent(false);
    }

    expect(['warning', 'critical', 'exhausted']).toContain(slo.evaluate());
  });
});

describe('CircuitBreaker', () => {
  it('opens after repeated failures and closes on success', async () => {
    const breaker = new CircuitBreaker(2, 5);

    breaker.onFailure();
    expect(breaker.state).toBe('closed');
    breaker.onFailure();
    expect(breaker.state).toBe('open');
    expect(breaker.canExecute()).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(breaker.state).toBe('half_open');
    breaker.onSuccess();
    expect(breaker.state).toBe('closed');
  });
});

describe('TraceCapture', () => {
  it('captures replay-friendly traces', () => {
    const capture = new TraceCapture('agent-1', 'summarize incident');
    const span = capture.startSpan('policy-check', 'policy_check', { action: 'read' });
    capture.finishSpan(span.spanId, 'ok', { decision: 'allow' }, undefined, 0.01);

    const trace = capture.finish('completed', true);
    expect(trace.agentId).toBe('agent-1');
    expect(trace.spans).toHaveLength(1);
    expect(trace.contentHash).toHaveLength(16);
    expect(trace.totalCostUsd).toBe(0.01);
  });
});

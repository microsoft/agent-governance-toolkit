// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, randomUUID } from 'crypto';

export interface MetricEvent {
  name: string;
  value: number | string;
  timestamp: string;
  attributes: Record<string, unknown>;
}

export interface MetricSink {
  record(event: MetricEvent): void;
}

export interface GovernanceMetricsConfig {
  enabled?: boolean;
  sinks?: MetricSink[];
}

export interface GovernanceMetricsSnapshot {
  counters: Record<string, number>;
  histograms: Record<string, number[]>;
  gauges: Record<string, number>;
  events: MetricEvent[];
}

export type SLOStatus = 'healthy' | 'warning' | 'critical' | 'exhausted';
export type CircuitBreakerState = 'closed' | 'open' | 'half_open';
export type TraceSpanStatus = 'ok' | 'error' | 'timeout';
export type TraceSpanKind = 'agent_task' | 'tool_call' | 'llm_inference' | 'delegation' | 'policy_check' | 'internal';

export interface ErrorBudgetSnapshot {
  targetAvailability: number;
  totalEvents: number;
  errorEvents: number;
  remainingPercent: number;
  burnRate: number;
  exhausted: boolean;
}

export interface TraceSpan {
  spanId: string;
  traceId: string;
  parentId?: string;
  name: string;
  kind: TraceSpanKind;
  status: TraceSpanStatus;
  startTime: string;
  endTime?: string;
  durationMs?: number;
  attributes: Record<string, unknown>;
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
}

export interface ExecutionTrace {
  traceId: string;
  agentId: string;
  taskInput: string;
  taskOutput?: string;
  startTime: string;
  endTime?: string;
  durationMs?: number;
  totalCostUsd: number;
  success?: boolean;
  spans: TraceSpan[];
  contentHash: string;
}

interface BudgetEvent {
  good: boolean;
  timestamp: number;
}

export class GovernanceMetrics {
  readonly enabled: boolean;
  private readonly sinks: MetricSink[];
  private readonly counters: Record<string, number> = {};
  private readonly histograms: Record<string, number[]> = {};
  private readonly gauges: Record<string, number> = {};
  private readonly events: MetricEvent[] = [];

  private static readonly MAX_HISTOGRAM_SAMPLES = 10_000;
  private static readonly MAX_EVENTS = 50_000;

  constructor(config: boolean | GovernanceMetricsConfig = false) {
    if (typeof config === 'boolean') {
      this.enabled = config;
      this.sinks = [];
    } else {
      this.enabled = config.enabled ?? false;
      this.sinks = config.sinks ?? [];
    }
  }

  registerSink(sink: MetricSink): void {
    this.sinks.push(sink);
  }

  recordPolicyDecision(
    decision: string,
    durationMs: number,
    attributes: Record<string, unknown> = {},
  ): void {
    this.incrementCounter(`policy.decision.${decision}`);
    this.recordHistogram('policy.duration_ms', durationMs);
    this.emit({
      name: 'policy.decision',
      value: decision,
      timestamp: new Date().toISOString(),
      attributes: {
        durationMs,
        ...attributes,
      },
    });
  }

  recordTrustScore(agentId: string, score: number): void {
    this.gauges[`trust.score.${agentId}`] = score;
    this.emit({
      name: 'trust.score',
      value: score,
      timestamp: new Date().toISOString(),
      attributes: { agentId },
    });
  }

  recordAuditEntry(seq: number): void {
    this.incrementCounter('audit.entries');
    this.gauges.auditLastSequence = seq;
    this.emit({
      name: 'audit.entry',
      value: seq,
      timestamp: new Date().toISOString(),
      attributes: {},
    });
  }

  recordToolCall(toolName: string, durationMs: number): void {
    this.incrementCounter('tool.calls');
    this.recordHistogram('tool.duration_ms', durationMs);
    this.emit({
      name: 'tool.call',
      value: durationMs,
      timestamp: new Date().toISOString(),
      attributes: { toolName },
    });
  }

  recordTrace(trace: ExecutionTrace): void {
    this.incrementCounter('trace.captures');
    this.recordHistogram('trace.duration_ms', trace.durationMs ?? 0);
    this.emit({
      name: 'trace.capture',
      value: trace.traceId,
      timestamp: new Date().toISOString(),
      attributes: {
        agentId: trace.agentId,
        success: trace.success ?? false,
        spanCount: trace.spans.length,
      },
    });
  }

  getSnapshot(): GovernanceMetricsSnapshot {
    return {
      counters: { ...this.counters },
      histograms: Object.fromEntries(
        Object.entries(this.histograms).map(([key, values]) => [key, [...values]]),
      ),
      gauges: { ...this.gauges },
      events: [...this.events],
    };
  }

  private incrementCounter(name: string): void {
    this.counters[name] = (this.counters[name] ?? 0) + 1;
  }

  private recordHistogram(name: string, value: number): void {
    const samples = this.histograms[name] ?? [];
    if (samples.length < GovernanceMetrics.MAX_HISTOGRAM_SAMPLES) {
      samples.push(value);
    } else {
      // Reservoir-style: overwrite a random older sample to bound memory.
      samples[Math.floor(Math.random() * samples.length)] = value;
    }
    this.histograms[name] = samples;
  }

  private emit(event: MetricEvent): void {
    if (!this.enabled) {
      return;
    }

    if (this.events.length >= GovernanceMetrics.MAX_EVENTS) {
      this.events.splice(0, Math.floor(GovernanceMetrics.MAX_EVENTS / 4));
    }
    this.events.push(event);
    for (const sink of this.sinks) {
      sink.record(event);
    }
  }
}

export class ErrorBudgetTracker {
  private readonly targetAvailability: number;
  private readonly windowSeconds: number;
  private readonly events: BudgetEvent[] = [];

  constructor(targetAvailability: number, windowSeconds: number = 30 * 24 * 60 * 60) {
    this.targetAvailability = targetAvailability;
    this.windowSeconds = windowSeconds;
  }

  recordEvent(good: boolean, timestampMs: number = Date.now()): void {
    this.events.push({ good, timestamp: timestampMs });
  }

  snapshot(windowSeconds: number = 3600): ErrorBudgetSnapshot {
    const relevant = this.events.filter((event) => event.timestamp >= Date.now() - this.windowSeconds * 1000);
    const totalEvents = relevant.length;
    const errorEvents = relevant.filter((event) => !event.good).length;
    const allowedErrorRate = 1 - this.targetAvailability;
    const actualErrorRate = totalEvents > 0 ? errorEvents / totalEvents : 0;
    const burnRate = allowedErrorRate > 0 ? actualErrorRate / allowedErrorRate : 0;
    const recent = relevant.filter((event) => event.timestamp >= Date.now() - windowSeconds * 1000);
    const recentErrors = recent.filter((event) => !event.good).length;
    const recentRate = recent.length > 0 ? recentErrors / recent.length : 0;

    return {
      targetAvailability: this.targetAvailability,
      totalEvents,
      errorEvents,
      remainingPercent: Math.max(0, (1 - (actualErrorRate / Math.max(allowedErrorRate, Number.EPSILON))) * 100),
      burnRate: allowedErrorRate > 0 ? recentRate / allowedErrorRate : burnRate,
      exhausted: actualErrorRate >= allowedErrorRate && totalEvents > 0,
    };
  }
}

export class SLOTracker {
  readonly name: string;
  readonly budget: ErrorBudgetTracker;

  constructor(name: string, targetAvailability: number, windowSeconds?: number) {
    this.name = name;
    this.budget = new ErrorBudgetTracker(targetAvailability, windowSeconds);
  }

  recordEvent(good: boolean, timestampMs?: number): void {
    this.budget.recordEvent(good, timestampMs);
  }

  evaluate(): SLOStatus {
    const snapshot = this.budget.snapshot();
    if (snapshot.exhausted) {
      return 'exhausted';
    }

    if (snapshot.burnRate >= 10) {
      return 'critical';
    }

    if (snapshot.burnRate >= 2) {
      return 'warning';
    }

    return 'healthy';
  }
}

export class CircuitBreaker {
  private failures = 0;
  private openedAt?: number;
  private currentState: CircuitBreakerState = 'closed';

  constructor(
    private readonly failureThreshold: number = 5,
    private readonly resetTimeoutMs: number = 30_000,
  ) {}

  get state(): CircuitBreakerState {
    if (this.currentState === 'open' && this.openedAt && Date.now() - this.openedAt >= this.resetTimeoutMs) {
      this.currentState = 'half_open';
    }

    return this.currentState;
  }

  canExecute(): boolean {
    return this.state !== 'open';
  }

  onSuccess(): void {
    this.failures = 0;
    this.currentState = 'closed';
    this.openedAt = undefined;
  }

  onFailure(): void {
    this.failures += 1;
    if (this.failures >= this.failureThreshold) {
      this.currentState = 'open';
      this.openedAt = Date.now();
    }
  }
}

export class TraceCapture {
  private readonly traceId = randomUUID().replace(/-/g, '');
  private readonly traceStart = Date.now();
  private readonly spans: TraceSpan[] = [];
  private readonly spanStarts = new Map<string, number>();
  private totalCostUsd = 0;

  constructor(
    private readonly agentId: string,
    private readonly taskInput: string = '',
  ) {}

  currentTraceId(): string {
    return this.traceId;
  }

  startSpan(
    name: string,
    kind: TraceSpanKind = 'internal',
    input?: Record<string, unknown>,
    parentId?: string,
    attributes: Record<string, unknown> = {},
  ): TraceSpan {
    const spanId = randomUUID().replace(/-/g, '').slice(0, 16);
    const startedAt = Date.now();
    this.spanStarts.set(spanId, startedAt);

    const span: TraceSpan = {
      spanId,
      traceId: this.traceId,
      parentId,
      name,
      kind,
      status: 'ok',
      startTime: new Date(startedAt).toISOString(),
      attributes,
      input,
    };

    this.spans.push(span);
    return span;
  }

  finishSpan(
    spanId: string,
    status: TraceSpanStatus = 'ok',
    output?: Record<string, unknown>,
    error?: string,
    costUsd: number = 0,
  ): void {
    const span = this.spans.find((item) => item.spanId === spanId);
    const startedAt = this.spanStarts.get(spanId);
    if (!span || startedAt === undefined) {
      throw new Error(`Unknown span: ${spanId}`);
    }

    const endedAt = Date.now();
    span.status = status;
    span.endTime = new Date(endedAt).toISOString();
    span.durationMs = endedAt - startedAt;
    span.output = output;
    span.error = error;
    this.totalCostUsd += costUsd;
    this.spanStarts.delete(spanId);
  }

  getSpanDuration(spanId: string): number | undefined {
    const span = this.spans.find((item) => item.spanId === spanId);
    return span?.durationMs;
  }

  finish(taskOutput?: string, success: boolean = true): ExecutionTrace {
    const endedAt = Date.now();
    const contentHash = createHash('sha256')
      .update(JSON.stringify({
        agentId: this.agentId,
        taskInput: this.taskInput,
        traceId: this.traceId,
      }))
      .digest('hex')
      .slice(0, 16);

    return {
      traceId: this.traceId,
      agentId: this.agentId,
      taskInput: this.taskInput,
      taskOutput,
      startTime: new Date(this.traceStart).toISOString(),
      endTime: new Date(endedAt).toISOString(),
      durationMs: endedAt - this.traceStart,
      totalCostUsd: this.totalCostUsd,
      success,
      spans: [...this.spans],
      contentHash,
    };
  }
}

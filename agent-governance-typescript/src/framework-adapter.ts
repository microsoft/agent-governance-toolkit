// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { AgentMeshClient } from './client';
import {
  ExecutionTrace,
  GovernanceMetrics,
  TraceCapture,
  TraceSpanKind,
  TraceSpanStatus,
} from './metrics';
import { GovernanceResult } from './types';

export interface FrameworkInvocation {
  name: string;
  kind?: TraceSpanKind;
  action?: string;
  /** Optional diagnostic identity hint; if provided, it must match the bound client identity. */
  agentId?: string;
  input?: Record<string, unknown>;
  attributes?: Record<string, unknown>;
}

export interface FrameworkInvocationOutcome<TOutput = unknown> {
  output?: TOutput;
  error?: string;
  status?: TraceSpanStatus;
  costUsd?: number;
}

export interface FrameworkAdapterResult<TOutput = unknown> {
  allowed: boolean;
  reason: string;
  action: string;
  invocation: FrameworkInvocation;
  governanceResult: GovernanceResult;
  output?: TOutput;
  error?: string;
  trace: ExecutionTrace;
}

export interface GenericFrameworkAdapterOptions {
  metrics?: GovernanceMetrics;
  actionPrefix?: string;
  actionResolver?: (invocation: FrameworkInvocation) => string;
}

export class FrameworkInvocationHandle<TOutput = unknown> {
  private finalized = false;
  private finalResult?: FrameworkAdapterResult<TOutput>;

  constructor(
    private readonly invocation: FrameworkInvocation,
    private readonly action: string,
    readonly allowed: boolean,
    readonly reason: string,
    readonly governanceResult: GovernanceResult,
    private readonly capture: TraceCapture | undefined,
    private readonly spanId: string | undefined,
    private readonly metrics: GovernanceMetrics | undefined,
  ) {}

  get traceId(): string | undefined {
    return this.capture?.currentTraceId();
  }

  toResult(): FrameworkAdapterResult<TOutput> {
    if (!this.finalized || !this.finalResult) {
      throw new Error('Invocation has not been completed');
    }

    return this.finalResult;
  }

  complete(outcome: FrameworkInvocationOutcome<TOutput> = {}): FrameworkAdapterResult<TOutput> {
    if (this.finalized) {
      throw new Error('Invocation already completed');
    }

    if (!this.capture || !this.spanId) {
      throw new Error('Invocation was already finalized during preflight');
    }

    const status = outcome.status ?? (outcome.error ? 'error' : 'ok');
    this.capture.finishSpan(
      this.spanId,
      status,
      normalizeOutput(outcome.output),
      outcome.error,
      outcome.costUsd ?? 0,
    );

    const durationMs = this.capture.getSpanDuration(this.spanId) ?? 0;
    if (this.invocation.kind === 'tool_call' && durationMs > 0) {
      this.metrics?.recordToolCall(this.invocation.name, durationMs);
    }

    const trace = this.capture.finish(
      outcome.output === undefined ? undefined : stringifyOutput(outcome.output),
      !outcome.error && status === 'ok',
    );
    this.metrics?.recordTrace(trace);

    this.finalResult = {
      allowed: this.allowed,
      reason: this.reason,
      action: this.action,
      invocation: this.invocation,
      governanceResult: this.governanceResult,
      output: outcome.output,
      error: outcome.error,
      trace,
    };
    this.finalized = true;
    return this.finalResult;
  }

  finalizeDenied(trace: ExecutionTrace): FrameworkAdapterResult<TOutput> {
    this.finalResult = {
      allowed: false,
      reason: this.reason,
      action: this.action,
      invocation: this.invocation,
      governanceResult: this.governanceResult,
      trace,
    };
    this.finalized = true;
    return this.finalResult;
  }
}

export class GenericFrameworkAdapter {
  private readonly metrics?: GovernanceMetrics;
  private readonly actionPrefix: string;
  private readonly actionResolver?: (invocation: FrameworkInvocation) => string;

  constructor(
    private readonly client: AgentMeshClient,
    options: GenericFrameworkAdapterOptions = {},
  ) {
    this.metrics = options.metrics;
    this.actionPrefix = options.actionPrefix ?? 'framework';
    this.actionResolver = options.actionResolver;
  }

  async beginInvocation<TOutput = unknown>(
    invocation: FrameworkInvocation,
  ): Promise<FrameworkInvocationHandle<TOutput>> {
    const action = this.resolveAction(invocation);
    const canonicalAgentId = this.client.identity.did;
    const assertedAgentId = invocation.agentId;
    const normalizedInvocation: FrameworkInvocation = {
      ...invocation,
      agentId: canonicalAgentId,
    };
    const identityMismatchReason = assertedAgentId && assertedAgentId !== canonicalAgentId
      ? `Caller-asserted agentId "${assertedAgentId}" does not match bound client identity "${canonicalAgentId}"`
      : undefined;
    const capture = new TraceCapture(
      canonicalAgentId,
      stringifyOutput(normalizedInvocation.input ?? {}),
    );
    const span = capture.startSpan(
      normalizedInvocation.name,
      normalizedInvocation.kind ?? 'internal',
      normalizedInvocation.input,
      undefined,
      {
        ...(normalizedInvocation.attributes ?? {}),
        ...(assertedAgentId ? { assertedAgentId } : {}),
      },
    );

    const governanceResult = identityMismatchReason
      ? this.rejectIdentityMismatch(action, canonicalAgentId, identityMismatchReason)
      : await this.client.executeWithGovernance(action, normalizedInvocation.input ?? {});
    this.metrics?.recordPolicyDecision(
      governanceResult.decision,
      governanceResult.executionTime,
      {
        action,
        invocationKind: normalizedInvocation.kind ?? 'internal',
      },
    );
    this.metrics?.recordTrustScore(
      canonicalAgentId,
      governanceResult.trustScore.overall,
    );
    this.metrics?.recordAuditEntry(this.client.audit.length);

    const allowed = governanceResult.decision === 'allow';
    const reason = identityMismatchReason ?? toReason(action, governanceResult);
    const handle = new FrameworkInvocationHandle<TOutput>(
      normalizedInvocation,
      action,
      allowed,
      reason,
      governanceResult,
      capture,
      span.spanId,
      this.metrics,
    );

    if (!allowed) {
      capture.finishSpan(
        span.spanId,
        'error',
        undefined,
        reason,
      );
      const trace = capture.finish(undefined, false);
      this.metrics?.recordTrace(trace);
      handle.finalizeDenied(trace);
    }

    return handle;
  }

  async run<TOutput>(
    invocation: FrameworkInvocation,
    handler: () => Promise<TOutput> | TOutput,
  ): Promise<FrameworkAdapterResult<TOutput>> {
    const handle = await this.beginInvocation<TOutput>(invocation);
    if (!handle.allowed) {
      return handle.toResult();
    }

    try {
      const output = await handler();
      return handle.complete({ output });
    } catch (error) {
      return handle.complete({
        error: error instanceof Error ? error.message : 'Unknown framework handler error',
        status: 'error',
      });
    }
  }

  private resolveAction(invocation: FrameworkInvocation): string {
    if (invocation.action) {
      return invocation.action;
    }

    if (this.actionResolver) {
      return this.actionResolver(invocation);
    }

    return `${this.actionPrefix}.${invocation.kind ?? 'internal'}.${invocation.name}`;
  }

  private rejectIdentityMismatch(
    action: string,
    agentId: string,
    reason: string,
  ): GovernanceResult {
    const auditEntry = this.client.audit.log({
      agentId,
      action,
      decision: 'deny',
    });
    this.client.trust.recordFailure(agentId);
    return {
      decision: 'deny',
      trustScore: this.client.trust.getTrustScore(agentId),
      auditEntry,
      executionTime: 0,
      lifecycleState: this.client.lifecycle.state,
    };
  }
}

function toReason(action: string, governanceResult: GovernanceResult): string {
  if (governanceResult.ringViolation) {
    return governanceResult.ringViolation.message;
  }

  if (governanceResult.decision === 'review') {
    return `Governance review required for action "${action}"`;
  }

  if (governanceResult.decision === 'deny') {
    return `Governance denied action "${action}"`;
  }

  return `Governance allowed action "${action}"`;
}

function normalizeOutput(output: unknown): Record<string, unknown> | undefined {
  if (output === undefined) {
    return undefined;
  }

  if (output !== null && typeof output === 'object' && !Array.isArray(output)) {
    return output as Record<string, unknown>;
  }

  return {
    value: output,
  };
}

function stringifyOutput(output: unknown): string {
  try {
    return JSON.stringify(output);
  } catch {
    return String(output);
  }
}

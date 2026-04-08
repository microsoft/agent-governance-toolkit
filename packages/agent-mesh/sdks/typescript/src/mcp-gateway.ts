// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from './credential-redactor';
import { MCPSlidingRateLimiter } from './mcp-sliding-rate-limiter';
import {
  ApprovalStatus,
  MCPAuditSink,
  MCPGatewayAuditEntry,
  MCPGatewayConfig,
  MCPGatewayDecisionResult,
  MCPMaybePromise,
  MCPResponseFinding,
  MCPSlidingRateLimitResult,
  MCPWrappedServerConfig,
} from './types';
import {
  createRegexScanBudget,
  debugSecurityFailure,
  DEFAULT_MCP_CLOCK,
  validateRegex,
} from './mcp-utils';

const BUILTIN_DANGEROUS_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/gi,
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/gi,
  /;\s*(?:rm|del|format|mkfs)\b/gi,
  /`[^`]+`/g,
];

export class InMemoryMCPAuditSink implements MCPAuditSink {
  private readonly entries: MCPGatewayAuditEntry[] = [];

  record(entry: MCPGatewayAuditEntry): void {
    this.entries.push(entry);
  }

  getEntries(): MCPGatewayAuditEntry[] {
    return [...this.entries];
  }
}

export class MCPGateway {
  private readonly deniedTools: string[];
  private readonly allowedTools: string[];
  private readonly sensitiveTools: string[];
  private readonly blockedPatterns: Array<string | RegExp>;
  private readonly enableBuiltinSanitization: boolean;
  private readonly approvalHandler?: MCPGatewayConfig['approvalHandler'];
  private readonly policyEvaluator?: MCPGatewayConfig['policyEvaluator'];
  private readonly metrics?: MCPGatewayConfig['metrics'];
  private readonly auditSink?: MCPAuditSink;
  private readonly clock: NonNullable<MCPGatewayConfig['clock']>;
  private readonly logger: MCPGatewayConfig['logger'];
  private readonly scanTimeoutMs: number;
  private readonly rateLimiter?: {
    consume(agentId: string): MCPMaybePromise<MCPSlidingRateLimitResult>;
  };
  private readonly redactor = new CredentialRedactor();
  private readonly auditEntries: MCPGatewayAuditEntry[] = [];

  constructor(config: MCPGatewayConfig = {}) {
    this.deniedTools = config.deniedTools ?? [];
    this.allowedTools = config.allowedTools ?? [];
    this.sensitiveTools = config.sensitiveTools ?? [];
    this.blockedPatterns = config.blockedPatterns ?? [];
    this.enableBuiltinSanitization = config.enableBuiltinSanitization ?? true;
    this.approvalHandler = config.approvalHandler;
    this.policyEvaluator = config.policyEvaluator;
    this.metrics = config.metrics;
    this.auditSink = config.auditSink;
    this.clock = config.clock ?? DEFAULT_MCP_CLOCK;
    this.logger = config.logger;
    this.scanTimeoutMs = config.scanTimeoutMs ?? 100;
    this.blockedPatterns.forEach((pattern) => {
      if (pattern instanceof RegExp) {
        validateRegex(pattern);
      }
    });
    this.rateLimiter =
      config.rateLimiter
      ?? (config.rateLimit
        ? new MCPSlidingRateLimiter(config.rateLimit)
        : undefined);
  }

  async evaluateToolCall(
    agentId: string,
    toolName: string,
    params: Record<string, unknown> = {},
  ): Promise<MCPGatewayDecisionResult> {
    try {
      return await this.evaluate(agentId, toolName, params);
    } catch (error) {
      debugSecurityFailure(this.logger, 'gateway.evaluateToolCall', error);
      return this.finalize(
        agentId,
        toolName,
        params,
        {
          allowed: false,
          reason: 'Internal gateway error - access denied (fail closed)',
          auditParams: this.redactor.redact(params).redacted as Record<string, unknown>,
          findings: [],
        },
      );
    }
  }

  get auditLog(): MCPGatewayAuditEntry[] {
    return [...this.auditEntries];
  }

  static wrapServer(
    serverConfig: Record<string, unknown>,
    config: MCPGatewayConfig = {},
  ): MCPWrappedServerConfig {
    return {
      serverConfig: { ...serverConfig },
      allowedTools: [...(config.allowedTools ?? [])],
      deniedTools: [...(config.deniedTools ?? [])],
      sensitiveTools: [...(config.sensitiveTools ?? [])],
      rateLimit: config.rateLimit,
    };
  }

  private async evaluate(
    agentId: string,
    toolName: string,
    params: Record<string, unknown>,
  ): Promise<MCPGatewayDecisionResult> {
    const auditParams = this.redactor.redact(params).redacted as Record<string, unknown>;
    const findings: MCPResponseFinding[] = [];

    if (this.deniedTools.includes(toolName)) {
      return this.finalize(agentId, toolName, params, {
        allowed: false,
        reason: `Tool '${toolName}' is on the deny list`,
        auditParams,
        findings,
      });
    }

    if (
      this.allowedTools.length > 0
      && !this.allowedTools.includes(toolName)
    ) {
      return this.finalize(agentId, toolName, params, {
        allowed: false,
        reason: `Tool '${toolName}' is not on the allow list`,
        auditParams,
        findings,
      });
    }

    const policyDecision = this.policyEvaluator?.evaluate(toolName, {
      agentId,
      ...params,
    });
    if (policyDecision === 'deny') {
      return this.finalize(agentId, toolName, params, {
        allowed: false,
        reason: `Policy denied tool '${toolName}'`,
        auditParams,
        findings,
        policyDecision,
      });
    }

    const sanitizationFinding = this.checkSanitization(params);
    if (sanitizationFinding) {
      findings.push(sanitizationFinding);
      return this.finalize(agentId, toolName, params, {
        allowed: false,
        reason: sanitizationFinding.message,
        auditParams,
        findings,
        policyDecision,
      });
    }

    const rateLimit = await this.rateLimiter?.consume(agentId);
    if (rateLimit && !rateLimit.allowed) {
      this.metrics?.recordMcpRateLimitHit(agentId, {
        toolName,
        retryAfterMs: rateLimit.retryAfterMs,
      });
      return this.finalize(agentId, toolName, params, {
        allowed: false,
        reason: `Agent '${agentId}' exceeded the MCP rate limit`,
        auditParams,
        findings,
        policyDecision,
        rateLimit,
      });
    }

    const requiresApproval =
      this.sensitiveTools.includes(toolName)
      || policyDecision === 'review';
    if (requiresApproval) {
      let approvalStatus = ApprovalStatus.Pending;
      if (this.approvalHandler) {
        approvalStatus = (await this.approvalHandler({
          agentId,
          toolName,
          params,
          auditParams,
          findings,
          policyDecision,
        })) ?? ApprovalStatus.Pending;
      }

      if (approvalStatus !== ApprovalStatus.Approved) {
        const reason = approvalStatus === ApprovalStatus.Denied
          ? 'Human approval denied'
          : 'Awaiting human approval';
        return this.finalize(agentId, toolName, params, {
          allowed: false,
          reason,
          auditParams,
          findings,
          approvalStatus,
          policyDecision,
          rateLimit,
        });
      }

      return this.finalize(agentId, toolName, params, {
        allowed: true,
        reason: 'Approved by human reviewer',
        auditParams,
        findings,
        approvalStatus,
        policyDecision,
        rateLimit,
      });
    }

    return this.finalize(agentId, toolName, params, {
      allowed: true,
      reason: 'Allowed by policy',
      auditParams,
      findings,
      policyDecision,
      rateLimit,
    });
  }

  private finalize(
    agentId: string,
    toolName: string,
    params: Record<string, unknown>,
    decision: MCPGatewayDecisionResult,
  ): MCPGatewayDecisionResult {
    const entry = {
      timestamp: new Date().toISOString(),
      agentId,
      toolName,
      params: decision.auditParams,
      auditParams: decision.auditParams,
      allowed: decision.allowed,
      reason: decision.reason,
      approvalStatus: decision.approvalStatus,
      policyDecision: decision.policyDecision,
      findings: decision.findings,
    };

    this.auditEntries.push(entry);
    this.auditSink?.record(entry);

    this.metrics?.recordMcpDecision(decision.allowed ? 'allow' : 'deny', {
      agentId,
      toolName,
      reason: decision.reason,
      approvalStatus: decision.approvalStatus ?? '',
    });

    if (decision.findings.length > 0) {
      this.metrics?.recordMcpThreatsDetected(decision.findings.length, {
        agentId,
        toolName,
      });
    }

    return decision;
  }

  private checkSanitization(
    params: Record<string, unknown>,
  ): MCPResponseFinding | undefined {
    const serialized = JSON.stringify(params);
    const budget = createRegexScanBudget(this.clock, this.scanTimeoutMs);

    for (const pattern of this.blockedPatterns) {
      budget.checkpoint('Regex scan exceeded time budget - access denied');
      if (
        (typeof pattern === 'string' && serialized.includes(pattern))
        || (pattern instanceof RegExp && pattern.test(serialized))
      ) {
        return {
          type: 'imperative_language',
          severity: 'critical',
          message: `Parameters matched blocked pattern: ${String(pattern)}`,
          matchedText: String(pattern),
          path: '$',
        };
      }
    }

    if (this.enableBuiltinSanitization) {
      if (hasShellExpansion(serialized)) {
        return {
          type: 'imperative_language',
          severity: 'critical',
          message: 'Parameters matched dangerous pattern: shell_expansion',
          matchedText: 'shell_expansion',
          path: '$',
        };
      }

      for (const pattern of BUILTIN_DANGEROUS_PATTERNS) {
        budget.checkpoint('Regex scan exceeded time budget - access denied');
        if (pattern.test(serialized)) {
          return {
            type: 'imperative_language',
            severity: 'critical',
            message: `Parameters matched dangerous pattern: ${pattern.source}`,
            matchedText: pattern.source,
            path: '$',
          };
        }
      }
    }

    return undefined;
  }
}

function hasShellExpansion(value: string): boolean {
  const startIndex = value.indexOf('$(');
  return startIndex !== -1 && value.indexOf(')', startIndex + 2) !== -1;
}

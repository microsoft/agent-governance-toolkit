// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from './credential-redactor';
import { McpSlidingRateLimiter } from './sliding-rate-limiter';
import { NoopMcpMetrics } from './stores';
import {
  ApprovalStatus,
  McpGatewayConfig,
  McpGatewayDecision,
  McpResponseFinding,
} from './types';
import {
  createRegexScanBudget,
  debugSecurityFailure,
  getSafeErrorMessage,
  hasMatch,
  stableStringify,
  SystemClock,
  validateRegex,
} from './utils';

const BUILTIN_DANGEROUS_PATTERNS = [
  /\b\d{3}-\d{2}-\d{4}\b/gi,
  /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/gi,
  /;\s*(?:rm|del|format|mkfs)\b/gi,
  /`[^`]+`/g,
];

/**
 * Enforces MCP gateway policy with deny, sanitization, rate-limit, and approval stages.
 */
export class McpGateway {
  private readonly config: McpGatewayConfig;
  private readonly redactor = new CredentialRedactor();

  constructor(config: McpGatewayConfig = {}) {
    this.config = {
      ...config,
      deniedTools: config.deniedTools ?? [],
      allowedTools: config.allowedTools ?? [],
      sensitiveTools: config.sensitiveTools ?? [],
      blockedPatterns: config.blockedPatterns ?? [],
      rateLimiter: config.rateLimiter ?? (
        config.rateLimit
          ? new McpSlidingRateLimiter(config.rateLimit)
          : undefined
      ),
      metrics: config.metrics ?? new NoopMcpMetrics(),
      clock: config.clock ?? new SystemClock(),
      scanTimeoutMs: config.scanTimeoutMs ?? 100,
    };
    this.config.blockedPatterns!.forEach((pattern) => {
      if (pattern instanceof RegExp) {
        validateRegex(pattern);
      }
    });
  }

  async evaluateToolCall(
    agentId: string,
    toolName: string,
    params: Record<string, unknown> = {},
  ): Promise<McpGatewayDecision> {
    try {
      const redactedParams = this.safeRedactParams(params);
      const findings: McpResponseFinding[] = [];

      if (this.config.deniedTools!.includes(toolName)) {
        return await this.finalize(agentId, toolName, 'policy', {
          allowed: false,
          reason: `Tool '${toolName}' is on the deny list`,
          redactedParams,
          findings,
        });
      }

      if (
        this.config.allowedTools!.length > 0
        && !this.config.allowedTools!.includes(toolName)
      ) {
        return await this.finalize(agentId, toolName, 'policy', {
          allowed: false,
          reason: `Tool '${toolName}' is not on the allow list`,
          redactedParams,
          findings,
        });
      }

      const policyDecision = await this.config.policyEvaluator?.evaluate(toolName, {
        agentId,
        ...params,
      });
      if (policyDecision === 'deny') {
        return await this.finalize(agentId, toolName, 'policy', {
          allowed: false,
          reason: `Policy denied tool '${toolName}'`,
          redactedParams,
          findings,
        });
      }

      const sanitizationFinding = this.checkSanitization(params);
      if (sanitizationFinding) {
        findings.push(sanitizationFinding);
        return await this.finalize(agentId, toolName, 'sanitization', {
          allowed: false,
          reason: sanitizationFinding.message,
          redactedParams,
          findings,
        });
      }

      const rateLimit = await this.config.rateLimiter?.consume(agentId);
      if (rateLimit && !rateLimit.allowed) {
        this.config.metrics!.recordRateLimitHit({ toolName, stage: 'rate_limit' });
        return await this.finalize(agentId, toolName, 'rate_limit', {
          allowed: false,
          reason: `Agent '${agentId}' exceeded the MCP rate limit`,
          redactedParams,
          findings,
          rateLimit,
        });
      }

      const requiresApproval =
        this.config.sensitiveTools!.includes(toolName)
        || policyDecision === 'review';
      if (requiresApproval) {
        const approvalStatus = this.config.approvalHandler
          ? (await this.config.approvalHandler({
            agentId,
            toolName,
            params,
            redactedParams,
            findings,
            stage: 'approval',
          })) ?? ApprovalStatus.Pending
          : ApprovalStatus.Pending;

        if (approvalStatus !== ApprovalStatus.Approved) {
          return await this.finalize(agentId, toolName, 'approval', {
            allowed: false,
            reason: approvalStatus === ApprovalStatus.Denied
              ? 'Human approval denied'
              : 'Awaiting human approval',
            redactedParams,
            findings,
            approvalStatus,
            rateLimit,
          });
        }

        return await this.finalize(agentId, toolName, 'approval', {
          allowed: true,
          reason: 'Approved by human reviewer',
          redactedParams,
          findings,
          approvalStatus,
          rateLimit,
        });
      }

      return await this.finalize(agentId, toolName, 'allow', {
        allowed: true,
        reason: 'Allowed by policy',
        redactedParams,
        findings,
        rateLimit,
      });
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'gateway.evaluateToolCall', error);
      return {
        allowed: false,
        reason: getSafeErrorMessage(error, 'Internal error - access denied (fail-closed)'),
        redactedParams: this.safeRedactParams(params),
        findings: [],
      };
    }
  }

  private async finalize(
    agentId: string,
    toolName: string,
    stage: string,
    decision: McpGatewayDecision,
  ): Promise<McpGatewayDecision> {
    try {
      await this.config.auditSink?.record({
        timestamp: this.config.clock!.now().toISOString(),
        stage,
        agentId,
        toolName,
        decision: decision.allowed ? 'allow' : 'deny',
        reason: decision.reason,
        approvalStatus: decision.approvalStatus,
        params: decision.redactedParams,
        findings: decision.findings.map((finding) => ({
          ...finding,
          matchedText: finding.type,
        })),
      });
      this.config.metrics!.recordDecision({
        toolName,
        decision: decision.allowed ? 'allow' : 'deny',
        stage,
      });
      if (decision.findings.length > 0) {
        this.config.metrics!.recordThreats(decision.findings.length, {
          toolName,
          stage,
        });
      }
      return decision;
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'gateway.finalize', error);
      return {
        allowed: false,
        reason: getSafeErrorMessage(error, 'Internal error - access denied (fail-closed)'),
        redactedParams: decision.redactedParams,
        findings: decision.findings.map((finding) => ({
          ...finding,
          matchedText: finding.type,
        })),
      };
    }
  }

  private checkSanitization(
    params: Record<string, unknown>,
  ): McpResponseFinding | undefined {
    const budget = createRegexScanBudget(this.config.clock, this.config.scanTimeoutMs);
    const serialized = stableStringify(params);
    for (const pattern of this.config.blockedPatterns!) {
      budget.checkpoint('Regex scan exceeded time budget - access denied');
      if (
        (typeof pattern === 'string' && serialized.includes(pattern))
        || (pattern instanceof RegExp && hasMatch(pattern, serialized))
      ) {
        return {
          type: 'imperative_language',
          severity: 'critical',
          message: `Parameters matched blocked pattern: ${String(pattern)}`,
          matchedText: 'blocked_pattern',
          path: '$',
        };
      }
    }
    for (const pattern of BUILTIN_DANGEROUS_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - access denied');
      if (hasMatch(pattern, serialized)) {
        return {
          type: 'imperative_language',
          severity: 'critical',
          message: `Parameters matched dangerous pattern: ${pattern.source}`,
          matchedText: 'dangerous_pattern',
          path: '$',
        };
      }
    }
    if (hasShellExpansion(serialized)) {
      return {
        type: 'imperative_language',
        severity: 'critical',
        message: 'Parameters matched dangerous pattern: shell_expansion',
        matchedText: 'shell_expansion',
        path: '$',
      };
    }
    return undefined;
  }

  private safeRedactParams(
    params: Record<string, unknown>,
  ): Record<string, unknown> {
    try {
      return this.redactor.redact(params).redacted as Record<string, unknown>;
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'gateway.safeRedactParams', error);
      return {};
    }
  }
}

function hasShellExpansion(value: string): boolean {
  const startIndex = value.indexOf('$(');
  return startIndex !== -1 && value.indexOf(')', startIndex + 2) !== -1;
}
